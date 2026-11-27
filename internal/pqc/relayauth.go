package pqc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// What a client proves to the relay: who is calling (a session key, agreed
// here under a full signature) and who may free an account without its
// device (a signature made from the recovery code). Neither puts anything on
// the wire that a listener could use again, and both hold in this package's
// threat model: the session key has to be dug out of FrodoKEM, the recovery
// signature is hash-based.

// --- relay sessions ---

// SessionKeySize is the size of the secret a session agreement yields, and
// of the key the relay hands out under it.
const SessionKeySize = 32

// ErrSession means a session key agreement failed.
var ErrSession = errors.New("pqc: session key agreement failed")

// SessionOffer holds the one-time private keys of a device that asks the
// relay for a session: X25519, ML-KEM-768 and FrodoKEM-976. The relay answers
// with one encapsulation for each, and the secret is made of all three, so a
// listener has to break all three to find it.
type SessionOffer struct {
	x, ml, frodo []byte // X25519 private key, ML-KEM and FrodoKEM seeds
	pub          []byte
}

// NewSessionOffer makes fresh one-time keys.
func NewSessionOffer() (*SessionOffer, error) {
	xPriv, xPub, err := x25519Generate()
	if err != nil {
		return nil, err
	}
	mlSeed, mlEK, err := kemMLKEM768.generate()
	if err != nil {
		return nil, err
	}
	frSeed, frEK, err := kemFrodo976.generate()
	if err != nil {
		return nil, err
	}
	pub := (&encoder{}).bytes(xPub).bytes(mlEK).bytes(frEK).b
	return &SessionOffer{x: xPriv, ml: mlSeed, frodo: frSeed, pub: pub}, nil
}

// Public is what the device sends: its three public keys. The device signs
// it, so nobody in between can swap in keys of their own.
func (o *SessionOffer) Public() []byte { return o.pub }

// SessionOfferSize is the size of an encoded offer.
func SessionOfferSize() int { return 3*4 + 32 + kemMLKEM768.ekSize() + kemFrodo976.ekSize() }

// AnswerSession is the relay's half: it encapsulates to the three keys of an
// offer. bind names what the session is for; both sides have to agree on it
// or they end up with different secrets.
func AnswerSession(offer, bind []byte) (answer, secret []byte, err error) {
	d := &decoder{b: offer}
	xPub := d.bytes(32)
	mlEK := d.bytes(kemMLKEM768.ekSize())
	frEK := d.bytes(kemFrodo976.ekSize())
	if !d.done() || len(xPub) != 32 || kemMLKEM768.checkEK(mlEK) != nil || kemFrodo976.checkEK(frEK) != nil {
		return nil, nil, ErrSession
	}
	ePriv, ePub, err := x25519Generate()
	if err != nil {
		return nil, nil, err
	}
	defer zero(ePriv)
	ssX, err := x25519(ePriv, xPub) // refuses low-order points
	if err != nil {
		return nil, nil, ErrSession
	}
	ssML, ctML, err := kemMLKEM768.encapsulate(mlEK)
	if err != nil {
		return nil, nil, ErrSession
	}
	ssFr, ctFr, err := kemFrodo976.encapsulate(frEK)
	if err != nil {
		return nil, nil, ErrSession
	}
	answer = (&encoder{}).bytes(ePub).bytes(ctML).bytes(ctFr).b
	return answer, sessionSecret(ssX, ssML, ssFr, offer, answer, bind), nil
}

// Open is the device's half: it decapsulates the relay's answer.
func (o *SessionOffer) Open(answer, bind []byte) ([]byte, error) {
	d := &decoder{b: answer}
	ePub := d.bytes(32)
	ctML := d.bytes(kemMLKEM768.ctSize())
	ctFr := d.bytes(kemFrodo976.ctSize())
	if !d.done() || len(ePub) != 32 || len(ctML) != kemMLKEM768.ctSize() || len(ctFr) != kemFrodo976.ctSize() {
		return nil, ErrSession
	}
	ssX, err := x25519(o.x, ePub)
	if err != nil {
		return nil, ErrSession
	}
	ssML, err := kemMLKEM768.decapsulate(o.ml, ctML)
	if err != nil {
		return nil, ErrSession
	}
	ssFr, err := kemFrodo976.decapsulate(o.frodo, ctFr)
	if err != nil {
		return nil, ErrSession
	}
	return sessionSecret(ssX, ssML, ssFr, o.pub, answer, bind), nil
}

func sessionSecret(ssX, ssML, ssFr, offer, answer, bind []byte) []byte {
	ikm := (&encoder{}).bytes(ssX).bytes(ssML).bytes(ssFr).b
	defer zero(ikm)
	th := sha512.Sum512((&encoder{}).bytes(offer).bytes(answer).bytes(bind).b)
	return kdf(th[:], ikm, "relay-session", SessionKeySize)
}

// WrapSessionKey encrypts the key the relay made for a session under the
// secret both sides now share. ad is authenticated with it.
func WrapSessionKey(secret, ad, key []byte) ([]byte, error) {
	if len(secret) != SessionKeySize || len(key) != SessionKeySize {
		return nil, ErrSession
	}
	return aeadSeal(secret, ad, key)
}

// UnwrapSessionKey is the device's side of WrapSessionKey.
func UnwrapSessionKey(secret, ad, box []byte) ([]byte, error) {
	if len(secret) != SessionKeySize {
		return nil, ErrSession
	}
	key, err := aeadOpen(secret, ad, box)
	if err != nil || len(key) != SessionKeySize {
		return nil, ErrSession
	}
	return key, nil
}

// --- recovery ---

const (
	// RecoveryCodeSize is the size of a recovery code.
	RecoveryCodeSize = 32
	// RecoveryPublicSize is the size of the public key a recovery code stands for.
	RecoveryPublicSize = slhPubSize
	// RecoverySigSize is the size of a signature made with a recovery code.
	RecoverySigSize = slhSigSize

	recoveryContext = "dm-recover"
)

// ErrRecovery means a recovery code or a signature made with one is no good.
var ErrRecovery = errors.New("pqc: invalid recovery code or signature")

// recoveryKey turns a recovery code into an SLH-DSA key pair. The code is
// stretched into the three seeds of FIPS 205 key generation (SK.seed, SK.prf,
// PK.seed, in the order the standard draws them), so the same code always
// gives the same key and the code itself never has to be shown to anyone.
func recoveryKey(code []byte) (*slhdsa.PrivateKey, []byte, error) {
	if len(code) != RecoveryCodeSize {
		return nil, nil, ErrRecovery
	}
	const n = slhPubSize / 2 // the security parameter: 32 bytes
	seeds := kdf(nil, code, "recovery-key", 3*n)
	defer zero(seeds)
	pub, priv, err := slhdsa.GenerateKey(bytes.NewReader(seeds), slhID)
	if err != nil {
		return nil, nil, err
	}
	pubB, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return &priv, pubB, nil
}

// RecoveryPublic returns the public key a recovery code stands for. That is
// what the relay stores.
func RecoveryPublic(code []byte) ([]byte, error) {
	_, pub, err := recoveryKey(code)
	return pub, err
}

// RecoverySign signs msg with the key a recovery code stands for.
func RecoverySign(code, msg []byte) ([]byte, error) {
	priv, _, err := recoveryKey(code)
	if err != nil {
		return nil, err
	}
	return slhdsa.SignRandomized(priv, rand.Reader, slhdsa.NewMessage(msg), []byte(sigContext(recoveryContext)))
}

// RecoveryVerify checks a signature made with RecoverySign.
func RecoveryVerify(pub, msg, sig []byte) error {
	if len(pub) != RecoveryPublicSize || len(sig) != RecoverySigSize {
		return ErrRecovery
	}
	key := slhdsa.PublicKey{ID: slhID}
	if err := key.UnmarshalBinary(pub); err != nil {
		return ErrRecovery
	}
	if !slhdsa.Verify(&key, slhdsa.NewMessage(msg), sig, []byte(sigContext(recoveryContext))) {
		return ErrRecovery
	}
	return nil
}
