package pqc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const (
	handshakeInfo = "ITTER-PQXDH-V1"
	rootInfo      = "ITTER-RK-V1"
	msgInfo       = "ITTER-MK-V1"
)

var (
	errNoSPK  = errors.New("pqc: signed prekey not found")
	errNoOTPK = errors.New("pqc: one-time prekey not found")
)

type InitialMessage struct {
	IKSign []byte   `json:"ik_sign"`
	IKDH   []byte   `json:"ik_dh"`
	EK     []byte   `json:"ek"`
	SPKID  uint32   `json:"spk_id"`
	OTPKID uint32   `json:"otpk_id,omitempty"`
	CT1    []byte   `json:"ct1"`
	CT2    []byte   `json:"ct2,omitempty"`
	Env    Envelope `json:"env"`
}

func kdfSK(parts ...[]byte) ([]byte, error) {
	ikm := bytes.Repeat([]byte{0xFF}, 32)
	for _, p := range parts {
		ikm = append(ikm, p...)
	}
	return hkdf.Key(sha256.New, ikm, nil, handshakeInfo, 32)
}

func Initiate(id *Identity, b *PublicBundle, plaintext []byte) (*Session, *InitialMessage, error) {
	if err := b.VerifySignature(); err != nil {
		return nil, nil, err
	}
	ikDH, err := id.dhPriv()
	if err != nil {
		return nil, nil, err
	}
	ek, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	dh1, err := dh(ikDH, b.SPKDHPub)
	if err != nil {
		return nil, nil, err
	}
	dh2, err := dh(ek, b.IKDHPub)
	if err != nil {
		return nil, nil, err
	}
	dh3, err := dh(ek, b.SPKDHPub)
	if err != nil {
		return nil, nil, err
	}
	spkKEM, err := mlkem.NewEncapsulationKey1024(b.SPKKEMPub)
	if err != nil {
		return nil, nil, err
	}
	ss1, ct1 := spkKEM.Encapsulate()

	var dh4, ss2, ct2 []byte
	if len(b.OTPKKEMPub) > 0 {
		if dh4, err = dh(ek, b.OTPKDHPub); err != nil {
			return nil, nil, err
		}
		opk, err := mlkem.NewEncapsulationKey1024(b.OTPKKEMPub)
		if err != nil {
			return nil, nil, err
		}
		ss2, ct2 = opk.Encapsulate()
	}

	sk, err := kdfSK(dh1, dh2, dh3, dh4, ss1, ss2)
	if err != nil {
		return nil, nil, err
	}
	zero(dh1)
	zero(dh2)
	zero(dh3)
	zero(dh4)
	zero(ss2)

	s := &Session{RK: sk, TheirSignPub: b.SignPub, TheirUsername: b.Username}
	if err := s.rotateSelf(); err != nil {
		return nil, nil, err
	}
	ratchetPriv, err := ecdh.X25519().NewPrivateKey(s.DHsPriv)
	if err != nil {
		return nil, nil, err
	}
	seed, err := dh(ratchetPriv, b.SPKDHPub)
	if err != nil {
		return nil, nil, err
	}
	s.RK, s.CKs, err = kdfRK(s.RK, append(seed, ss1...))
	zero(seed)
	zero(ss1)
	if err != nil {
		return nil, nil, err
	}

	h := s.header()
	mk, err := s.nextSendKey()
	if err != nil {
		return nil, nil, err
	}
	body, err := sealBody(mk, headerAD(&h), plaintext)
	zero(mk)
	if err != nil {
		return nil, nil, err
	}

	im := &InitialMessage{
		IKSign: id.SignPub, IKDH: id.DHPub, EK: ek.PublicKey().Bytes(),
		SPKID: b.SPKID, OTPKID: b.OTPKID, CT1: ct1, CT2: ct2,
		Env: Envelope{Header: h, Body: body},
	}
	return s, im, nil
}

func Respond(id *Identity, spk *SignedPreKey, otpk *OneTimePreKey, im *InitialMessage) (*Session, []byte, error) {
	if spk == nil || spk.ID != im.SPKID {
		return nil, nil, errNoSPK
	}
	spkDH, err := ecdh.X25519().NewPrivateKey(spk.DHPriv)
	if err != nil {
		return nil, nil, err
	}
	spkKEM, err := mlkem.NewDecapsulationKey1024(spk.KEMPriv)
	if err != nil {
		return nil, nil, err
	}
	ikDH, err := id.dhPriv()
	if err != nil {
		return nil, nil, err
	}
	dh1, err := dh(spkDH, im.IKDH)
	if err != nil {
		return nil, nil, err
	}
	dh2, err := dh(ikDH, im.EK)
	if err != nil {
		return nil, nil, err
	}
	dh3, err := dh(spkDH, im.EK)
	if err != nil {
		return nil, nil, err
	}
	ss1, err := spkKEM.Decapsulate(im.CT1)
	if err != nil {
		return nil, nil, err
	}

	var dh4, ss2 []byte
	if im.OTPKID != 0 {
		if otpk == nil || otpk.ID != im.OTPKID {
			return nil, nil, errNoOTPK
		}
		opkDH, err := ecdh.X25519().NewPrivateKey(otpk.DHPriv)
		if err != nil {
			return nil, nil, err
		}
		opkKEM, err := mlkem.NewDecapsulationKey1024(otpk.KEMPriv)
		if err != nil {
			return nil, nil, err
		}
		if dh4, err = dh(opkDH, im.EK); err != nil {
			return nil, nil, err
		}
		if ss2, err = opkKEM.Decapsulate(im.CT2); err != nil {
			return nil, nil, err
		}
	}

	sk, err := kdfSK(dh1, dh2, dh3, dh4, ss1, ss2)
	if err != nil {
		return nil, nil, err
	}
	zero(dh1)
	zero(dh2)
	zero(dh3)
	zero(dh4)
	zero(ss2)

	s := &Session{
		RK:           sk,
		DHsPub:       spk.DHPub,
		DHsPriv:      spk.DHPriv,
		KEMsPub:      spk.KEMPub,
		KEMsPriv:     spk.KEMPriv,
		TheirSignPub: im.IKSign,
	}
	if err := s.receiveRotation(&im.Env.Header, ss1); err != nil {
		return nil, nil, err
	}
	zero(ss1)
	pt, err := s.Decrypt(&im.Env)
	if err != nil {
		return nil, nil, err
	}
	return s, pt, nil
}