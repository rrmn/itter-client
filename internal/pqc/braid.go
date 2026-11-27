package pqc

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
)

// The KEM braid is the Sparse Continuous Key Agreement at the heart of SPQR
// (Signal's ML-KEM Braid protocol). Each epoch one party (the initiator of
// that epoch) samples a fresh KEM key pair and streams the encapsulation key
// as erasure-coded chunks piggybacked on ordinary messages; the other party
// encapsulates to it and streams the ciphertext back. Both derive the epoch
// secret, then the roles swap for the next epoch.
//
// Differences from Signal's braid: ML-KEM's incremental interface is not
// used (Go's ML-KEM does not expose it, and FrodoKEM has none), so the
// ciphertext is sent after the full encapsulation key has arrived. The
// authenticator, epochs and erasure coding follow the specification.

type braidParams struct {
	kem   kemScheme
	chunk int
	label string
}

var (
	// braidMLKEM heals fast (5+5 chunks of 256 bytes per epoch).
	braidMLKEM = &braidParams{kem: kemMLKEM768, chunk: 256, label: "spqr/ml-kem-768"}
	// braidFrodo carries the load if lattices with ring structure fall
	// (4+4 chunks of 4096 bytes per epoch).
	braidFrodo = &braidParams{kem: kemFrodo976, chunk: 4096, label: "spqr/frodokem-976"}
)

const (
	stKeysUnsampled uint8 = iota + 1 // epoch initiator, no key pair yet
	stEkSending                      // initiator streaming ek || mac
	stCtReceiving                    // initiator collecting ct || mac
	stNoEkReceived                   // epoch responder collecting ek || mac
	stEkReceived                     // responder has ek, encapsulates on next send
	stCtSending                      // responder streaming ct || mac
	stBroken                         // protocol violation by the peer: this ratchet stays where it is
)

const (
	mtNone uint8 = 0
	mtEk   uint8 = 1
	mtCt   uint8 = 2
)

const braidMACSize = 32

var errBraidAuth = errors.New("pqc: PQ ratchet authentication failed")

type braidMsg struct {
	Epoch uint64
	Type  uint8
	Index uint16
	Data  []byte
}

type epochKey struct {
	Epoch  uint64
	Secret []byte
}

type authState struct {
	Root []byte `json:"r"`
	Mac  []byte `json:"m"`
}

// Braid is the serialisable SCKA state of one PQ ratchet.
type Braid struct {
	St   uint8      `json:"st"`
	Ep   uint64     `json:"ep"`
	Auth authState  `json:"auth"`
	DK   []byte     `json:"dk,omitempty"` // initiator's decapsulation seed
	EK   []byte     `json:"ek,omitempty"` // responder's received encapsulation key
	Enc  *rsEncoder `json:"enc,omitempty"`
	Dec  *rsDecoder `json:"dec,omitempty"`
	Err  string     `json:"err,omitempty"` // why the ratchet is in stBroken
	// Fails counts reconstructions in a row whose MAC did not verify.
	Fails int `json:"fails,omitempty"`
}

// maxBraidFails is how often a reconstruction may fail its MAC before the
// ratchet is frozen. One failure can happen innocently (the peer restarted
// an epoch after losing state, so chunks of two keys got mixed): the decoder
// is then emptied and collects afresh.
const maxBraidFails = 3

func (b *Braid) badMAC() error {
	b.Fails++
	if b.Fails >= maxBraidFails {
		return errBraidAuth
	}
	return nil
}

// halt freezes the ratchet after a protocol violation. Messages keep flowing
// on the chain keys agreed so far; only further post-quantum healing stops.
func (b *Braid) halt(err error) {
	b.St, b.Err = stBroken, err.Error()
	b.DK, b.EK, b.Enc, b.Dec = nil, nil, nil, nil
}

// Stalled reports whether the ratchet was frozen, and why.
func (b *Braid) Stalled() (bool, string) { return b.St == stBroken, b.Err }

func be64(v uint64) string { return string(binary.BigEndian.AppendUint64(nil, v)) }
func be32(v uint32) string { return string(binary.BigEndian.AppendUint32(nil, v)) }

func newBraid(p *braidParams, sk []byte, initiator bool) *Braid {
	b := &Braid{Ep: 1, Auth: authState{Root: make([]byte, 32)}}
	b.Auth.update(p, 1, sk)
	if initiator {
		b.St = stKeysUnsampled
	} else {
		b.St = stNoEkReceived
	}
	return b
}

func (a *authState) update(p *braidParams, epoch uint64, key []byte) {
	out := kdf(nil, append(append([]byte(nil), a.Root...), key...), p.label+"/auth-update"+be64(epoch), 64)
	a.Root, a.Mac = out[:32], out[32:]
}

func (a *authState) mac(p *braidParams, what string, epoch uint64, data []byte) []byte {
	h := hmac.New(sha512.New, a.Mac)
	h.Write([]byte(labelPrefix + p.label + "/" + what + be64(epoch)))
	h.Write(data)
	return h.Sum(nil)[:braidMACSize]
}

func epochSecret(p *braidParams, kemSS []byte, epoch uint64) []byte {
	return kdf(nil, kemSS, p.label+"/epoch-secret"+be64(epoch), 32)
}

// sendingEpoch is the PQ chain epoch the next outgoing message must use.
func (b *Braid) sendingEpoch() uint64 { return b.Ep - 1 }

// send returns the braid message to piggyback on the next outgoing message,
// and the epoch secret if this send completed a key agreement.
func (b *Braid) send(p *braidParams) (braidMsg, *epochKey, error) {
	switch b.St {
	case stKeysUnsampled:
		dk, ek, err := p.kem.generate()
		if err != nil {
			return braidMsg{}, nil, err
		}
		b.DK = dk
		b.Enc = newRSEncoder(append(ek, b.Auth.mac(p, "ek", b.Ep, ek)...), p.chunk)
		b.St = stEkSending
		idx, cw := b.Enc.next()
		return braidMsg{b.Ep, mtEk, idx, cw}, nil, nil
	case stEkSending:
		idx, cw := b.Enc.next()
		return braidMsg{b.Ep, mtEk, idx, cw}, nil, nil
	case stCtReceiving, stNoEkReceived, stBroken:
		return braidMsg{Epoch: b.Ep, Type: mtNone}, nil, nil
	case stEkReceived:
		kss, ct, err := p.kem.encapsulate(b.EK)
		if err != nil {
			// The peer sent an invalid encapsulation key. That stalls this PQ
			// ratchet (which the peer could do anyway by sending nothing),
			// but it must not stop the conversation.
			return braidMsg{Epoch: b.Ep, Type: mtNone}, nil, nil
		}
		ss := epochSecret(p, kss, b.Ep)
		zero(kss)
		b.Auth.update(p, b.Ep, ss)
		b.Enc = newRSEncoder(append(ct, b.Auth.mac(p, "ct", b.Ep, ct)...), p.chunk)
		b.EK = nil
		b.St = stCtSending
		idx, cw := b.Enc.next()
		return braidMsg{b.Ep, mtCt, idx, cw}, &epochKey{b.Ep, ss}, nil
	case stCtSending:
		idx, cw := b.Enc.next()
		return braidMsg{b.Ep, mtCt, idx, cw}, nil, nil
	}
	return braidMsg{}, nil, errors.New("pqc: corrupt PQ ratchet state")
}

// receive processes an (already authenticated) braid message and returns the
// epoch secret if it completed a key agreement. Stale or out-of-phase
// messages are ignored.
func (b *Braid) receive(p *braidParams, m braidMsg) (*epochKey, error) {
	switch b.St {
	case stEkSending, stCtReceiving:
		if m.Epoch != b.Ep || m.Type != mtCt {
			return nil, nil
		}
		if b.Dec == nil { // first ct chunk: the peer has our whole ek, stop sending it
			b.Dec = newRSDecoder(p.kem.ctSize()+braidMACSize, p.chunk)
			b.Enc = nil
			b.St = stCtReceiving
		}
		if err := b.Dec.add(m.Index, m.Data); err != nil {
			return nil, err
		}
		if !b.Dec.complete() {
			return nil, nil
		}
		data, err := b.Dec.message()
		if err != nil {
			return nil, err
		}
		ct, mac := data[:p.kem.ctSize()], data[p.kem.ctSize():]
		kss, err := p.kem.decapsulate(b.DK, ct)
		if err != nil {
			return nil, err
		}
		ss := epochSecret(p, kss, b.Ep)
		zero(kss)
		next := b.Auth // update replaces the slices, so this is a safe copy
		next.update(p, b.Ep, ss)
		if !hmac.Equal(mac, next.mac(p, "ct", b.Ep, ct)) {
			b.Dec = newRSDecoder(p.kem.ctSize()+braidMACSize, p.chunk)
			return nil, b.badMAC()
		}
		b.Auth, b.Fails = next, 0
		key := &epochKey{b.Ep, ss}
		b.Ep++
		b.St, b.DK, b.Dec = stNoEkReceived, nil, nil
		return key, nil
	case stNoEkReceived:
		if m.Epoch != b.Ep || m.Type != mtEk {
			return nil, nil
		}
		if b.Dec == nil {
			b.Dec = newRSDecoder(p.kem.ekSize()+braidMACSize, p.chunk)
		}
		if err := b.Dec.add(m.Index, m.Data); err != nil {
			return nil, err
		}
		if !b.Dec.complete() {
			return nil, nil
		}
		data, err := b.Dec.message()
		if err != nil {
			return nil, err
		}
		ek, mac := data[:p.kem.ekSize()], data[p.kem.ekSize():]
		if !hmac.Equal(mac, b.Auth.mac(p, "ek", b.Ep, ek)) {
			b.Dec = nil
			return nil, b.badMAC()
		}
		if err := p.kem.checkEK(ek); err != nil {
			return nil, err // authenticated but not a key: the peer broke the protocol
		}
		b.EK, b.St, b.Dec, b.Fails = ek, stEkReceived, nil, 0
		return nil, nil
	case stCtSending:
		if m.Epoch == b.Ep+1 { // the peer finished this epoch; we initiate the next
			b.Ep++
			b.St, b.Enc = stKeysUnsampled, nil
		}
		return nil, nil
	case stKeysUnsampled, stEkReceived, stBroken:
		return nil, nil
	}
	return nil, errors.New("pqc: corrupt PQ ratchet state")
}
