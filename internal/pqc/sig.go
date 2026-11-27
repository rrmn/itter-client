package pqc

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// Composite signatures: Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s.
//
// A signature carries all three and only verifies if all three do, so
// forging one requires breaking SLH-DSA, which rests on nothing but the hash
// function. There is no lighter variant: SLH-DSA takes about half a second to
// sign, and what cannot wait that long (requests to the relay) is
// authenticated with a key agreed under such a signature instead.

const (
	slhID          = slhdsa.SHA2_256s
	ed25519SigSize = ed25519.SignatureSize
	mldsaSigSize   = 4627 // ML-DSA-87
	mldsaPubSize   = 2592
	slhSigSize     = 29792 // SLH-DSA-SHA2-256s
	slhPubSize     = 64
	slhPrivSize    = 128

	// FullSigSize is the size of a signature. FastSigSize is how much of it
	// the Ed25519 and ML-DSA parts take; the SLH-DSA part follows.
	FullSigSize = ed25519SigSize + mldsaSigSize + slhSigSize
	FastSigSize = ed25519SigSize + mldsaSigSize
)

var errBadSig = errors.New("pqc: invalid signature")

// SigningKey is the private half of a composite signing identity.
type SigningKey struct {
	Ed25519 []byte `json:"ed25519"` // 64-byte private key
	MLDSA   []byte `json:"mldsa"`   // 32-byte seed
	SLHDSA  []byte `json:"slhdsa"`  // FIPS 205 private key
}

// VerifyingKey is the public half.
type VerifyingKey struct {
	Ed25519 []byte `json:"ed25519"`
	MLDSA   []byte `json:"mldsa"`
	SLHDSA  []byte `json:"slhdsa"`
}

func generateSigningKey() (*SigningKey, *VerifyingKey, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ml, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, nil, err
	}
	slhPub, slhPriv, err := slhdsa.GenerateKey(rand.Reader, slhID)
	if err != nil {
		return nil, nil, err
	}
	slhPrivB, err := slhPriv.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	slhPubB, err := slhPub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return &SigningKey{Ed25519: edPriv, MLDSA: ml.Bytes(), SLHDSA: slhPrivB},
		&VerifyingKey{Ed25519: edPub, MLDSA: ml.PublicKey().Bytes(), SLHDSA: slhPubB}, nil
}

func sigContext(ctx string) string { return labelPrefix + "sig/" + ctx }

func (k *SigningKey) signFast(msg []byte, ctx string) ([]byte, error) {
	c := sigContext(ctx)
	if len(k.Ed25519) != ed25519.PrivateKeySize {
		return nil, errBadSig
	}
	edSig, err := ed25519.PrivateKey(k.Ed25519).Sign(nil, msg, &ed25519.Options{Context: c})
	if err != nil {
		return nil, err
	}
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), k.MLDSA)
	if err != nil {
		return nil, err
	}
	mlSig, err := ml.Sign(rand.Reader, msg, &mldsa.Options{Context: c})
	if err != nil {
		return nil, err
	}
	return append(edSig, mlSig...), nil
}

// SignFull produces an Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s signature.
func (k *SigningKey) SignFull(msg []byte, ctx string) ([]byte, error) {
	out, err := k.signFast(msg, ctx)
	if err != nil {
		return nil, err
	}
	priv := slhdsa.PrivateKey{ID: slhID}
	if err := priv.UnmarshalBinary(k.SLHDSA); err != nil {
		return nil, err
	}
	slhSig, err := slhdsa.SignRandomized(&priv, rand.Reader, slhdsa.NewMessage(msg), []byte(sigContext(ctx)))
	if err != nil {
		return nil, err
	}
	return append(out, slhSig...), nil
}

func (vk *VerifyingKey) verifyFast(msg, sig []byte, ctx string) error {
	c := sigContext(ctx)
	if len(sig) < FastSigSize || len(vk.Ed25519) != ed25519.PublicKeySize {
		return errBadSig
	}
	if ed25519.VerifyWithOptions(ed25519.PublicKey(vk.Ed25519), msg, sig[:ed25519SigSize], &ed25519.Options{Context: c}) != nil {
		return errBadSig
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), vk.MLDSA)
	if err != nil {
		return errBadSig
	}
	if mldsa.Verify(pk, msg, sig[ed25519SigSize:FastSigSize], &mldsa.Options{Context: c}) != nil {
		return errBadSig
	}
	return nil
}

// VerifyFull checks all three component signatures.
func (vk *VerifyingKey) VerifyFull(msg, sig []byte, ctx string) error {
	if len(sig) != FullSigSize {
		return errBadSig
	}
	if err := vk.verifyFast(msg, sig[:FastSigSize], ctx); err != nil {
		return err
	}
	pub := slhdsa.PublicKey{ID: slhID}
	if err := pub.UnmarshalBinary(vk.SLHDSA); err != nil {
		return errBadSig
	}
	if !slhdsa.Verify(&pub, slhdsa.NewMessage(msg), sig[FastSigSize:], []byte(sigContext(ctx))) {
		return errBadSig
	}
	return nil
}
