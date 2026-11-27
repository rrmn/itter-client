package pqc

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Identity is a device's long-term private identity (stored in the vault).
type Identity struct {
	V      int         `json:"v"`
	Sign   *SigningKey `json:"sign"`
	DHPriv []byte      `json:"dh_priv"` // X25519 identity key
	Pub    IdentityKey `json:"pub"`
}

// IdentityKey is the public composite identity. Its canonical encoding is
// what fingerprints, safety numbers, pins and the relay all refer to, so the
// X25519 key used in the handshake is bound to the signature keys.
type IdentityKey struct {
	VerifyingKey
	X25519 []byte `json:"x25519"`
}

const identityMagic = "ITK2"

// GenerateIdentity creates a fresh composite identity.
func GenerateIdentity() (*Identity, error) {
	sk, vk, err := generateSigningKey()
	if err != nil {
		return nil, err
	}
	dhPriv, dhPub, err := x25519Generate()
	if err != nil {
		return nil, err
	}
	return &Identity{V: ProtocolVersion, Sign: sk, DHPriv: dhPriv,
		Pub: IdentityKey{VerifyingKey: *vk, X25519: dhPub}}, nil
}

// Valid reports whether the identity is a complete v2 identity.
func (id *Identity) Valid() bool {
	return id != nil && id.V == ProtocolVersion && id.Sign != nil && len(id.DHPriv) == 32 &&
		len(id.Pub.Ed25519) == 32 && len(id.Pub.MLDSA) == mldsaPubSize && len(id.Pub.SLHDSA) == slhPubSize
}

// Encode returns the canonical encoding of the public identity.
func (k *IdentityKey) Encode() []byte {
	e := &encoder{}
	e.raw([]byte(identityMagic)).bytes(k.Ed25519).bytes(k.MLDSA).bytes(k.SLHDSA).bytes(k.X25519)
	return e.b
}

// DecodeIdentityKey parses and size-checks an encoded identity.
func DecodeIdentityKey(b []byte) (*IdentityKey, error) {
	d := &decoder{b: b}
	if string(d.take(4)) != identityMagic {
		return nil, errors.New("pqc: not a v2 identity key")
	}
	k := &IdentityKey{}
	k.Ed25519 = d.bytes(64)
	k.MLDSA = d.bytes(mldsaPubSize)
	k.SLHDSA = d.bytes(slhPubSize)
	k.X25519 = d.bytes(32)
	if !d.done() || len(k.Ed25519) != 32 || len(k.MLDSA) != mldsaPubSize ||
		len(k.SLHDSA) != slhPubSize || len(k.X25519) != 32 {
		return nil, errors.New("pqc: malformed identity key")
	}
	return k, nil
}

// Equal compares two encoded identities.
func IdentityEqual(a, b []byte) bool { return len(a) > 0 && bytes.Equal(a, b) }

// IdentityID is a short public identifier of an encoded identity. Senders tell
// the relay which identity they encrypted for, so the relay can refuse a
// message meant for an identity the recipient no longer has.
func IdentityID(identity []byte) string {
	sum := sha512.Sum512(append([]byte(labelPrefix+"identity-id"), identity...))
	return hex.EncodeToString(sum[:16])
}

// Fingerprint is a human-comparable digest of one encoded identity: 256 bits,
// so that even a quantum search for a second identity with the same
// fingerprint is out of reach.
func Fingerprint(identity []byte) string {
	sum := sha512.Sum512(append([]byte(labelPrefix+"fingerprint"), identity...))
	h := hex.EncodeToString(sum[:32])
	var groups []string
	for i := 0; i < len(h); i += 8 {
		groups = append(groups, h[i:i+8])
	}
	return strings.Join(groups, " ")
}

// SafetyNumber is the 60-digit number both parties compare out of band. It
// covers every public key of both identities (including the SLH-DSA key), so
// a matching number authenticates the conversation even if every
// non-hash-based algorithm is broken.
func SafetyNumber(a, b []byte) string {
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	e := &encoder{}
	e.raw([]byte(labelPrefix + "safety-number")).bytes(a).bytes(b)
	sum := sha512.Sum512(e.b)
	n := new(big.Int).SetBytes(sum[:])
	n.Mod(n, new(big.Int).Exp(big.NewInt(10), big.NewInt(60), nil))
	s := fmt.Sprintf("%060d", n)
	var groups []string
	for i := 0; i < 60; i += 5 {
		groups = append(groups, s[i:i+5])
	}
	return strings.Join(groups, " ")
}

// --- prekeys ---

// PreKeyPublic is the public part of a prekey: one key per KEM family.
type PreKeyPublic struct {
	ID    uint32 `json:"id"`
	DH    []byte `json:"dh"`    // X25519
	MLKEM []byte `json:"mlkem"` // ML-KEM-1024
	Frodo []byte `json:"frodo"` // FrodoKEM-1344
}

// PreKey is a prekey with its private seeds. Public keys are re-derived from
// the seeds on demand, which keeps the vault small.
type PreKey struct {
	ID        uint32 `json:"id"`
	DHPriv    []byte `json:"dh_priv"`
	MLKEMSeed []byte `json:"mlkem_seed"`
	FrodoSeed []byte `json:"frodo_seed"`
	Sig       []byte `json:"sig,omitempty"` // signed prekeys only
	Created   int64  `json:"created"`
}

func generatePreKey(id uint32) (*PreKey, *PreKeyPublic, error) {
	dhPriv, dhPub, err := x25519Generate()
	if err != nil {
		return nil, nil, err
	}
	mlSeed, mlPub, err := kemMLKEM1024.generate()
	if err != nil {
		return nil, nil, err
	}
	frSeed, frPub, err := kemFrodo1344.generate()
	if err != nil {
		return nil, nil, err
	}
	return &PreKey{ID: id, DHPriv: dhPriv, MLKEMSeed: mlSeed, FrodoSeed: frSeed, Created: time.Now().Unix()},
		&PreKeyPublic{ID: id, DH: dhPub, MLKEM: mlPub, Frodo: frPub}, nil
}

// Public re-derives the public keys.
func (k *PreKey) Public() (*PreKeyPublic, error) {
	sk, err := ecdhPublic(k.DHPriv)
	if err != nil {
		return nil, err
	}
	ml, err := kemMLKEM1024.publicFromSeed(k.MLKEMSeed)
	if err != nil {
		return nil, err
	}
	fr, err := kemFrodo1344.publicFromSeed(k.FrodoSeed)
	if err != nil {
		return nil, err
	}
	return &PreKeyPublic{ID: k.ID, DH: sk, MLKEM: ml, Frodo: fr}, nil
}

// SPKPayload is what the identity signs for a signed prekey.
func SPKPayload(identity []byte, p *PreKeyPublic) []byte {
	e := &encoder{}
	e.raw([]byte(labelPrefix + "spk")).bytes(identity).u32(p.ID).bytes(p.DH).bytes(p.MLKEM).bytes(p.Frodo)
	return e.b
}

// GenerateSignedPreKey creates a prekey signed with the full composite
// signature (this takes ~0.5 s because of SLH-DSA).
func GenerateSignedPreKey(id *Identity, spkID uint32) (*PreKey, *PreKeyPublic, error) {
	k, pub, err := generatePreKey(spkID)
	if err != nil {
		return nil, nil, err
	}
	sig, err := id.Sign.SignFull(SPKPayload(id.Pub.Encode(), pub), "spk")
	if err != nil {
		return nil, nil, err
	}
	k.Sig = sig
	return k, pub, nil
}

// GenerateOneTimePreKey creates an unsigned one-time prekey.
func GenerateOneTimePreKey(id uint32) (*PreKey, *PreKeyPublic, error) { return generatePreKey(id) }

// Valid checks the sizes of all public keys.
func (p *PreKeyPublic) Valid() bool {
	return p != nil && len(p.DH) == 32 && len(p.MLKEM) == kemMLKEM1024.ekSize() && len(p.Frodo) == kemFrodo1344.ekSize()
}

// PublicBundle is what the relay serves for a user.
type PublicBundle struct {
	Username string        `json:"username"`
	Identity []byte        `json:"identity"`
	SPK      *PreKeyPublic `json:"spk"`
	SPKSig   []byte        `json:"spk_sig"`
	OTPK     *PreKeyPublic `json:"otpk,omitempty"`
}

// Verify decodes the identity and checks the signed prekey's full signature.
func (b *PublicBundle) Verify() (*IdentityKey, error) {
	ik, err := DecodeIdentityKey(b.Identity)
	if err != nil {
		return nil, err
	}
	if !b.SPK.Valid() {
		return nil, errors.New("pqc: malformed signed prekey")
	}
	if b.OTPK != nil && !b.OTPK.Valid() {
		return nil, errors.New("pqc: malformed one-time prekey")
	}
	if err := ik.VerifyFull(SPKPayload(b.Identity, b.SPK), b.SPKSig, "spk"); err != nil {
		return nil, errors.New("pqc: invalid signed prekey signature")
	}
	return ik, nil
}
