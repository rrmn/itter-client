package pqc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// Release signatures. itter's releases are signed with a composite key of
// the same kind as an identity (Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s), so
// a forged release needs SLH-DSA broken, like a forged identity. They are
// made under a context of their own, so a release signature can never pass
// for anything else, nor anything else for one.
//
// The program carries the public half and checks every update with it. The
// private half stays on the maintainer's computer.

const releaseContext = "release"

// ReleaseKeySize is the size of an encoded release (verifying) key.
const ReleaseKeySize = ed25519.PublicKeySize + mldsaPubSize + slhPubSize

// ReleaseSigSize is the size of a release signature.
const ReleaseSigSize = FullSigSize

// ErrReleaseKey means bytes that should be a release key are not one.
var ErrReleaseKey = errors.New("pqc: not a release key")

// GenerateReleaseKey makes a new release key pair.
func GenerateReleaseKey() (*SigningKey, *VerifyingKey, error) { return generateSigningKey() }

// SignRelease signs msg as a release.
func (k *SigningKey) SignRelease(msg []byte) ([]byte, error) { return k.SignFull(msg, releaseContext) }

// VerifyRelease checks a signature made with SignRelease.
func (vk *VerifyingKey) VerifyRelease(msg, sig []byte) error {
	return vk.VerifyFull(msg, sig, releaseContext)
}

// ReleaseKeyBytes encodes a verifying key as its three public keys, one
// after the other.
func (vk *VerifyingKey) ReleaseKeyBytes() ([]byte, error) {
	if len(vk.Ed25519) != ed25519.PublicKeySize || len(vk.MLDSA) != mldsaPubSize || len(vk.SLHDSA) != slhPubSize {
		return nil, ErrReleaseKey
	}
	out := make([]byte, 0, ReleaseKeySize)
	out = append(out, vk.Ed25519...)
	out = append(out, vk.MLDSA...)
	return append(out, vk.SLHDSA...), nil
}

// ParseReleaseKey decodes what ReleaseKeyBytes made.
func ParseReleaseKey(b []byte) (*VerifyingKey, error) {
	if len(b) != ReleaseKeySize {
		return nil, ErrReleaseKey
	}
	b = bytes.Clone(b)
	e, m := ed25519.PublicKeySize, ed25519.PublicKeySize+mldsaPubSize
	return &VerifyingKey{Ed25519: b[:e], MLDSA: b[e:m], SLHDSA: b[m:]}, nil
}

// ReleaseKeyFingerprint is what people compare to know they have the right
// release key: the first 16 bytes of its SHA-256, in groups of four hex
// digits.
func ReleaseKeyFingerprint(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	h := hex.EncodeToString(sum[:16])
	var groups []string
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:i+4])
	}
	return strings.Join(groups, " ")
}

// Matches reports whether vk is the verifying half of k. It is how a key
// file is checked for consistency before anything is signed with it.
func (k *SigningKey) Matches(vk *VerifyingKey) bool {
	if len(k.Ed25519) != ed25519.PrivateKeySize {
		return false
	}
	if !bytes.Equal(ed25519.PrivateKey(k.Ed25519).Public().(ed25519.PublicKey), vk.Ed25519) {
		return false
	}
	// The other two halves are checked the honest way: sign and verify.
	sig, err := k.SignFull([]byte("itter release key check"), "release-key-check")
	if err != nil {
		return false
	}
	return vk.VerifyFull([]byte("itter release key check"), sig, "release-key-check") == nil
}
