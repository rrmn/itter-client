package pqc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
)

const (
	MaxSkippedKeys = 1000
	MaxSkip        = 500
)

var errDecrypt = errors.New("pqc: decryption failed")

type Session struct {
	RK            []byte            `json:"rk"`
	DHsPub        []byte            `json:"dhs_pub"`
	DHsPriv       []byte            `json:"dhs_priv"`
	KEMsPub       []byte            `json:"kems_pub"`
	KEMsPriv      []byte            `json:"kems_priv"`
	DHr           []byte            `json:"dhr,omitempty"`
	KEMr          []byte            `json:"kemr,omitempty"`
	CKs           []byte            `json:"cks,omitempty"`
	CKr           []byte            `json:"ckr,omitempty"`
	Ns            uint32            `json:"ns"`
	Nr            uint32            `json:"nr"`
	PN            uint32            `json:"pn"`
	PendingCT     []byte            `json:"pending_ct,omitempty"`
	LastCT        []byte            `json:"last_ct,omitempty"`
	Skipped       map[string][]byte `json:"skipped,omitempty"`
	TheirSignPub  []byte            `json:"their_sign_pub,omitempty"`
	TheirUsername string            `json:"their_username,omitempty"`
}

type Header struct {
	DH  []byte `json:"dh"`
	KEM []byte `json:"kem"`
	CT  []byte `json:"ct,omitempty"`
	PN  uint32 `json:"pn"`
	N   uint32 `json:"n"`
}

type Envelope struct {
	Header Header `json:"hdr"`
	Body   []byte `json:"body"`
}

func (s *Session) Encrypt(plaintext []byte) (*Envelope, error) {
	h := s.header()
	mk, err := s.nextSendKey()
	if err != nil {
		return nil, err
	}
	body, err := sealBody(mk, headerAD(&h), plaintext)
	zero(mk)
	if err != nil {
		return nil, err
	}
	return &Envelope{Header: h, Body: body}, nil
}

func (s *Session) Decrypt(env *Envelope) ([]byte, error) {
	h := &env.Header
	if mk, ok := s.Skipped[skipKeyID(h.DH, h.N)]; ok {
		pt, err := openBody(mk, headerAD(h), env.Body)
		if err != nil {
			return nil, errDecrypt
		}
		delete(s.Skipped, skipKeyID(h.DH, h.N))
		zero(mk)
		return pt, nil
	}

	if !bytes.Equal(h.DH, s.DHr) {
		if err := s.skipMessageKeys(h.PN); err != nil {
			return nil, err
		}
		if err := s.receiveRotation(h, nil); err != nil {
			return nil, err
		}
	}
	if err := s.skipMessageKeys(h.N); err != nil {
		return nil, err
	}
	if s.CKr == nil {
		return nil, errors.New("pqc: no receiving chain")
	}
	nextCK, mk := kdfCK(s.CKr)
	pt, err := openBody(mk, headerAD(h), env.Body)
	if err != nil {
		zero(mk)
		return nil, errDecrypt
	}
	s.CKr = nextCK
	s.Nr++
	zero(mk)
	return pt, nil
}

func (s *Session) receiveRotation(h *Header, injectedSS []byte) error {
	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0

	ss := injectedSS
	if ss == nil && len(h.CT) > 0 && !bytes.Equal(h.CT, s.LastCT) {
		dk, err := mlkem.NewDecapsulationKey1024(s.KEMsPriv)
		if err != nil {
			return err
		}
		ss, err = dk.Decapsulate(h.CT)
		if err != nil {
			return err
		}
		s.LastCT = append([]byte(nil), h.CT...)
	}

	s.DHr = append([]byte(nil), h.DH...)
	s.KEMr = append([]byte(nil), h.KEM...)

	oldSelf, err := ecdh.X25519().NewPrivateKey(s.DHsPriv)
	if err != nil {
		return err
	}
	sharedR, err := dh(oldSelf, s.DHr)
	if err != nil {
		return err
	}
	s.RK, s.CKr, err = kdfRK(s.RK, append(sharedR, ss...))
	zero(sharedR)
	zero(ss)
	if err != nil {
		return err
	}

	if err := s.rotateSelf(); err != nil {
		return err
	}
	ek, err := mlkem.NewEncapsulationKey1024(s.KEMr)
	if err != nil {
		return err
	}
	sharedS, ct := ek.Encapsulate()
	s.PendingCT = ct

	newSelf, err := ecdh.X25519().NewPrivateKey(s.DHsPriv)
	if err != nil {
		return err
	}
	sharedD, err := dh(newSelf, s.DHr)
	if err != nil {
		return err
	}
	s.RK, s.CKs, err = kdfRK(s.RK, append(sharedD, sharedS...))
	zero(sharedD)
	zero(sharedS)
	return err
}

func (s *Session) rotateSelf() error {
	d, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	k, err := mlkem.GenerateKey1024()
	if err != nil {
		return err
	}
	s.DHsPriv, s.DHsPub = d.Bytes(), d.PublicKey().Bytes()
	s.KEMsPriv, s.KEMsPub = k.Bytes(), k.EncapsulationKey().Bytes()
	return nil
}

func (s *Session) header() Header {
	return Header{DH: s.DHsPub, KEM: s.KEMsPub, CT: s.PendingCT, PN: s.PN, N: s.Ns}
}

func (s *Session) nextSendKey() ([]byte, error) {
	if s.CKs == nil {
		return nil, errors.New("pqc: no sending chain")
	}
	next, mk := kdfCK(s.CKs)
	s.CKs = next
	s.Ns++
	return mk, nil
}

func (s *Session) skipMessageKeys(until uint32) error {
	if s.CKr == nil || until <= s.Nr {
		return nil
	}
	if until-s.Nr > MaxSkip {
		return errors.New("pqc: too many skipped messages")
	}
	if s.Skipped == nil {
		s.Skipped = map[string][]byte{}
	}
	for s.Nr < until {
		if len(s.Skipped) >= MaxSkippedKeys {
			return errors.New("pqc: skipped-key store full")
		}
		next, mk := kdfCK(s.CKr)
		s.Skipped[skipKeyID(s.DHr, s.Nr)] = mk
		s.CKr = next
		s.Nr++
	}
	return nil
}

func skipKeyID(dhPub []byte, n uint32) string {
	return hex.EncodeToString(dhPub) + ":" + strconv.Itoa(int(n))
}

func kdfRK(rk, ikm []byte) (newRK, ck []byte, err error) {
	out, err := hkdf.Key(sha256.New, ikm, rk, rootInfo, 64)
	if err != nil {
		return nil, nil, err
	}
	return out[:32], out[32:], nil
}

func kdfCK(ck []byte) (next, mk []byte) {
	h1 := hmac.New(sha256.New, ck)
	h1.Write([]byte{0x01})
	mk = h1.Sum(nil)
	h2 := hmac.New(sha256.New, ck)
	h2.Write([]byte{0x02})
	next = h2.Sum(nil)
	return
}

func headerAD(h *Header) []byte {
	b, _ := json.Marshal(h)
	return b
}

func sealBody(mk, ad, plaintext []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, mk, nil, msgInfo, 32)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, ad), nil
}

func openBody(mk, ad, body []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, mk, nil, msgInfo, 32)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	if len(body) < 12 {
		return nil, errDecrypt
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, body[:12], body[12:], ad)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}