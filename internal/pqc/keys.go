package pqc

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

type Identity struct {
	SignPub  []byte `json:"sign_pub"`
	SignPriv []byte `json:"sign_priv"`
	DHPub    []byte `json:"dh_pub"`
	DHPriv   []byte `json:"dh_priv"`
}

func GenerateIdentity() (*Identity, error) {
	spub, spriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{
		SignPub:  spub,
		SignPriv: spriv,
		DHPub:    dh.PublicKey().Bytes(),
		DHPriv:   dh.Bytes(),
	}, nil
}

func (id *Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(id.SignPriv), msg)
}

func (id *Identity) dhPriv() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(id.DHPriv)
}

func dh(priv *ecdh.PrivateKey, pubBytes []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

type SignedPreKey struct {
	ID      uint32 `json:"id"`
	DHPub   []byte `json:"dh_pub"`
	DHPriv  []byte `json:"dh_priv"`
	KEMPub  []byte `json:"kem_pub"`
	KEMPriv []byte `json:"kem_priv"`
	Sig     []byte `json:"sig"`
	Created int64  `json:"created"`
}

func SPKSigningPayload(id uint32, dhPub, kemPub []byte) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], id)
	out := append([]byte("ITTER-SPK-V1"), b[:]...)
	out = append(out, dhPub...)
	out = append(out, kemPub...)
	return out
}

func GenerateSignedPreKey(id *Identity, spkID uint32) (*SignedPreKey, error) {
	dhk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	spk := &SignedPreKey{
		ID:      spkID,
		DHPub:   dhk.PublicKey().Bytes(),
		DHPriv:  dhk.Bytes(),
		KEMPub:  kk.EncapsulationKey().Bytes(),
		KEMPriv: kk.Bytes(),
		Created: time.Now().Unix(),
	}
	spk.Sig = id.Sign(SPKSigningPayload(spk.ID, spk.DHPub, spk.KEMPub))
	return spk, nil
}

type OneTimePreKey struct {
	ID      uint32 `json:"id"`
	DHPub   []byte `json:"dh_pub"`
	DHPriv  []byte `json:"dh_priv"`
	KEMPub  []byte `json:"kem_pub"`
	KEMPriv []byte `json:"kem_priv"`
}

func GenerateOneTimePreKey(id uint32) (*OneTimePreKey, error) {
	dhk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	return &OneTimePreKey{
		ID:      id,
		DHPub:   dhk.PublicKey().Bytes(),
		DHPriv:  dhk.Bytes(),
		KEMPub:  kk.EncapsulationKey().Bytes(),
		KEMPriv: kk.Bytes(),
	}, nil
}

type PublicBundle struct {
	Username   string `json:"username"`
	SignPub    []byte `json:"sign_pub"`
	IKDHPub    []byte `json:"ik_dh_pub"`
	SPKID      uint32 `json:"spk_id"`
	SPKDHPub   []byte `json:"spk_dh_pub"`
	SPKKEMPub  []byte `json:"spk_kem_pub"`
	SPKSig     []byte `json:"spk_sig"`
	OTPKID     uint32 `json:"otpk_id,omitempty"`
	OTPKDHPub  []byte `json:"otpk_dh_pub,omitempty"`
	OTPKKEMPub []byte `json:"otpk_kem_pub,omitempty"`
}

func (b *PublicBundle) VerifySignature() error {
	if !ed25519.Verify(ed25519.PublicKey(b.SignPub),
		SPKSigningPayload(b.SPKID, b.SPKDHPub, b.SPKKEMPub), b.SPKSig) {
		return errors.New("pqc: invalid signed prekey signature")
	}
	return nil
}