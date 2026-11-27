package pqc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"
)

// Session is one Triple Ratchet conversation. Three independent ratchets
// each yield a key for every message:
//
//	DR   classic Double Ratchet (X25519 + HMAC chains)
//	PQ1  SPQR over ML-KEM-768   (fast post-quantum healing)
//	PQ2  SPQR over FrodoKEM-976 (survives a break of ring/module lattices)
//
// and the AEAD key is HKDF(salt = pq1_mk || pq2_mk, ikm = dr_mk), so an
// attacker has to break all three to read a message.
type Session struct {
	V           int            `json:"v"`
	Initiator   bool           `json:"initiator"`
	AD          []byte         `json:"ad"`
	DR          *DR            `json:"dr"`
	PQ1         *Braid         `json:"pq1"`
	PQ1Chain    *PQChain       `json:"pq1_chain"`
	PQ2         *Braid         `json:"pq2"`
	PQ2Chain    *PQChain       `json:"pq2_chain"`
	HandshakeID []byte         `json:"hs_id"`
	PendingInit *InitHandshake `json:"pending_init,omitempty"` // kept until the peer replies
	// InitSends counts how often the relay took a message that carried the
	// handshake, and InitSentAt is when it last did (unix seconds). See Seal.
	InitSends     uint32 `json:"init_sends,omitempty"`
	InitSentAt    int64  `json:"init_sent,omitempty"`
	TheirIdentity []byte `json:"their_identity"`
	TheirUsername string `json:"their_username,omitempty"`
	// Trusted is no longer used (trust is recorded per contact in the vault);
	// it is only read when migrating older vaults.
	Trusted bool `json:"trusted,omitempty"`
}

// Valid reports whether s is a usable v2 session (older sessions are dropped).
func (s *Session) Valid() bool {
	return s != nil && s.V == ProtocolVersion && s.DR != nil && s.PQ1 != nil && s.PQ2 != nil &&
		s.PQ1Chain != nil && s.PQ2Chain != nil
}

const (
	headerMagic = "TR"
	padBlock    = 64
	maxEnvelope = 1 << 20
)

type header struct {
	dr       drHeader
	pq1, pq2 braidMsg
	n1, n2   uint32
}

func encodeBraidMsg(e *encoder, m braidMsg, n uint32) {
	e.u64(m.Epoch).u8(m.Type).u16(m.Index).u16(uint16(len(m.Data))).raw(m.Data).u32(n)
}

func decodeBraidMsg(d *decoder, p *braidParams) (braidMsg, uint32, error) {
	var m braidMsg
	m.Epoch = d.u64()
	m.Type = d.u8()
	m.Index = d.u16()
	l := int(d.u16())
	m.Data = d.take(l)
	n := d.u32()
	if d.err || m.Epoch == 0 || n == 0 {
		return m, 0, errMalformed
	}
	switch m.Type {
	case mtNone:
		if l != 0 {
			return m, 0, errMalformed
		}
	case mtEk, mtCt:
		if l != p.chunk {
			return m, 0, errMalformed
		}
	default:
		return m, 0, errMalformed
	}
	return m, n, nil
}

func (h *header) encode() []byte {
	e := &encoder{}
	e.raw([]byte(headerMagic)).u8(ProtocolVersion)
	e.raw(h.dr.DH).u32(h.dr.PN).u32(h.dr.N)
	encodeBraidMsg(e, h.pq1, h.n1)
	encodeBraidMsg(e, h.pq2, h.n2)
	return e.b
}

func decodeHeader(b []byte) (*header, error) {
	d := &decoder{b: b}
	if string(d.take(2)) != headerMagic || d.u8() != ProtocolVersion {
		return nil, errMalformed
	}
	h := &header{}
	h.dr.DH = d.take(32)
	h.dr.PN = d.u32()
	h.dr.N = d.u32()
	var err error
	if h.pq1, h.n1, err = decodeBraidMsg(d, braidMLKEM); err != nil {
		return nil, err
	}
	if h.pq2, h.n2, err = decodeBraidMsg(d, braidFrodo); err != nil {
		return nil, err
	}
	if !d.done() {
		return nil, errMalformed
	}
	return h, nil
}

func hybridKey(drMK, pq1MK, pq2MK []byte) []byte {
	salt := append(append([]byte(nil), pq1MK...), pq2MK...)
	return kdf(salt, drMK, "tr/message-key", 32)
}

func pad(pt []byte) []byte {
	n := 4 + len(pt)
	n += (padBlock - n%padBlock) % padBlock
	out := make([]byte, n)
	binary.BigEndian.PutUint32(out, uint32(len(pt)))
	copy(out[4:], pt)
	return out
}

func unpad(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, errMalformed
	}
	n := uint64(binary.BigEndian.Uint32(b))
	if n > uint64(len(b)-4) {
		return nil, errMalformed
	}
	return b[4 : 4+int(n)], nil
}

func (s *Session) clone() (*Session, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var c Session
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Session) ad(hdr []byte) []byte {
	return append(append(make([]byte, 0, len(s.AD)+len(hdr)), s.AD...), hdr...)
}

// Encrypt seals plaintext and advances all three ratchets.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	c, err := s.clone()
	if err != nil {
		return nil, err
	}
	h := &header{}
	var drMK []byte
	if h.dr, drMK, err = c.DR.sendKey(); err != nil {
		return nil, err
	}
	var mk1, mk2 []byte
	if h.pq1, h.n1, mk1, err = c.pqSend(braidMLKEM, c.PQ1, c.PQ1Chain); err != nil {
		return nil, err
	}
	if h.pq2, h.n2, mk2, err = c.pqSend(braidFrodo, c.PQ2, c.PQ2Chain); err != nil {
		return nil, err
	}
	hdr := h.encode()
	mk := hybridKey(drMK, mk1, mk2)
	ct, err := aeadSeal(mk, c.ad(hdr), pad(plaintext))
	zero(mk)
	if err != nil {
		return nil, err
	}

	env := binary.BigEndian.AppendUint32(nil, uint32(len(hdr)))
	env = append(append(env, hdr...), ct...)
	*s = *c
	return env, nil
}

func (s *Session) pqSend(p *braidParams, b *Braid, ch *PQChain) (braidMsg, uint32, []byte, error) {
	m, key, err := b.send(p)
	if err != nil {
		return m, 0, nil, err
	}
	if key != nil {
		if err := ch.addEpoch(p, key); err != nil {
			return m, 0, nil, err
		}
	}
	n, mk, err := ch.sendKey(p, b.sendingEpoch())
	return m, n, mk, err
}

// Decrypt opens an envelope. All state changes happen on a copy that is only
// committed after the AEAD tag verifies, so forged, replayed or corrupted
// messages can never damage the session.
func (s *Session) Decrypt(env []byte) ([]byte, error) {
	if len(env) < 4 || len(env) > maxEnvelope {
		return nil, errMalformed
	}
	hl64 := uint64(binary.BigEndian.Uint32(env))
	if hl64 > uint64(len(env)-4) { // compared before converting: int is 32 bits on some platforms
		return nil, errMalformed
	}
	hl := int(hl64)
	hdr, ct := env[4:4+hl], env[4+hl:]
	h, err := decodeHeader(hdr)
	if err != nil {
		return nil, err
	}

	c, err := s.clone()
	if err != nil {
		return nil, err
	}
	drMK, err := c.DR.recvKey(h.dr)
	if err != nil {
		return nil, decryptErr(err)
	}
	mk1, err := c.PQ1Chain.recvKey(braidMLKEM, h.pq1.Epoch-1, h.n1)
	if err != nil {
		return nil, decryptErr(err)
	}
	mk2, err := c.PQ2Chain.recvKey(braidFrodo, h.pq2.Epoch-1, h.n2)
	if err != nil {
		return nil, decryptErr(err)
	}
	mk := hybridKey(drMK, mk1, mk2)
	padded, err := aeadOpen(mk, c.ad(hdr), ct)
	zero(mk)
	if err != nil {
		return nil, errDecrypt
	}
	pt, err := unpad(padded)
	if err != nil {
		return nil, err
	}

	// Authenticated: now let the PQ ratchets consume their chunks. A ratchet
	// that hits a protocol violation is frozen, but the message, which is
	// authentic, is still delivered.
	if err := c.pqRecv(braidMLKEM, c.PQ1, c.PQ1Chain, h.pq1); err != nil {
		c.PQ1.halt(err)
	}
	if err := c.pqRecv(braidFrodo, c.PQ2, c.PQ2Chain, h.pq2); err != nil {
		c.PQ2.halt(err)
	}
	c.PendingInit = nil // the peer has the session
	*s = *c
	return pt, nil
}

// decryptErr keeps "already received" distinguishable from every other
// failure, which all collapse into ErrDecrypt.
func decryptErr(err error) error {
	if errors.Is(err, ErrDuplicate) {
		return ErrDuplicate
	}
	return errDecrypt
}

func (s *Session) pqRecv(p *braidParams, b *Braid, ch *PQChain, m braidMsg) error {
	key, err := b.receive(p, m)
	if err != nil {
		return err
	}
	if key != nil {
		return ch.addEpoch(p, key)
	}
	return nil
}

// PQEpochs reports how many post-quantum key agreements each PQ ratchet has
// While the peer has not answered, the handshake goes along again after
// ReattachFirst without an answer, then after twice that, and so on, but at
// least every ReattachMax.
var (
	ReattachFirst = 10 * time.Minute
	ReattachMax   = 24 * time.Hour
)

// AwaitsReply reports whether the peer has not answered in this session yet.
func (s *Session) AwaitsReply() bool { return s.PendingInit != nil }

// handshakeDue decides whether the next message carries the handshake.
//
// Until the relay has taken one that did, every message does. After that the
// relay delivers in order, so the peer has the handshake before anything
// that follows, and a device that only ever reads is not sent 120 KB with
// every single message. But the relay taking a message proves nothing about
// the peer: it may never have arrived (the relay drops, silently, what an
// ignored sender writes, and what a device that was away for too long has no
// room for). So until the peer answers, the handshake goes along again once
// in a while, less and less often. Whatever went wrong then heals by itself.
func (s *Session) handshakeDue() bool {
	if s.PendingInit == nil {
		return false
	}
	if s.InitSends == 0 {
		return true
	}
	wait := ReattachFirst
	for i := uint32(1); i < s.InitSends && wait < ReattachMax; i++ {
		wait *= 2
	}
	wait = min(wait, ReattachMax)
	since := time.Now().Unix() - s.InitSentAt
	return since < 0 || since >= int64(wait/time.Second)
}

// HandshakeDelivered records that the relay took a message carrying the
// handshake. Several messages that carried it at the same time count once.
func (s *Session) HandshakeDelivered() {
	if !s.handshakeDue() {
		return
	}
	if s.InitSends < 1<<20 {
		s.InitSends++
	}
	s.InitSentAt = time.Now().Unix()
}

// completed (useful for status displays and tests).
func (s *Session) PQEpochs() (mlkem, frodo uint64) { return s.PQ1Chain.CurEpoch, s.PQ2Chain.CurEpoch }

// PQStalled reports a frozen PQ ratchet ("" if both are healthy).
func (s *Session) PQStalled() string {
	if ok, why := s.PQ1.Stalled(); ok {
		return "ML-KEM ratchet: " + why
	}
	if ok, why := s.PQ2.Stalled(); ok {
		return "FrodoKEM ratchet: " + why
	}
	return ""
}
