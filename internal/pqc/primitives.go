// Package pqc implements itter's end-to-end encryption: a PQXDH-style
// handshake followed by a Triple Ratchet (Signal's Double Ratchet running in
// parallel with sparse post-quantum ratchets), hardened for a threat model in
// which RSA, elliptic curves AND structured lattices are all assumed broken.
//
// Every layer is a hybrid in which the strongest assumption carries the load:
//
//	key exchange:  X25519 + ML-KEM + FrodoKEM   (FrodoKEM is plain LWE, no ring)
//	signatures:    Ed25519 + ML-DSA + SLH-DSA    (SLH-DSA is hash-based)
//	symmetric:     HKDF-SHA-512, HMAC-SHA-512, AES-256-GCM
//
// Breaking a message requires breaking FrodoKEM (and ML-KEM and X25519);
// forging an identity requires breaking SLH-DSA (and ML-DSA and Ed25519).
// No RSA is used anywhere.
package pqc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
)

// ProtocolVersion is carried in every wire payload and every stored session.
const ProtocolVersion = 2

const labelPrefix = "itter/v2/"

var (
	// ErrDecrypt means a message could not be authenticated or decrypted.
	ErrDecrypt = errors.New("pqc: decryption failed")
	// ErrDuplicate means the message was already received (or is so old that
	// its key has been discarded). It is harmless: relays may redeliver.
	ErrDuplicate = errors.New("pqc: message already received")
	// ErrMalformed means the bytes are not a well-formed message.
	ErrMalformed = errors.New("pqc: malformed message")

	errDecrypt   = ErrDecrypt
	errMalformed = ErrMalformed
)

// kdf is HKDF-SHA-512.
func kdf(salt, ikm []byte, info string, n int) []byte {
	out, err := hkdf.Key(sha512.New, ikm, salt, labelPrefix+info, n)
	if err != nil {
		panic(err) // only possible for absurd output lengths
	}
	return out
}

const aeadNonceSize = 12

// aeadSeal encrypts with a message key. Message keys are meant to be used
// once, but the nonce is random anyway: if ratchet state is ever rolled back
// (a crash before saving, a restored backup, a synced folder), a reused
// message key must not turn into AES-GCM nonce reuse.
func aeadSeal(mk, ad, pt []byte) ([]byte, error) {
	nonce := make([]byte, aeadNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aeadFromKey(mk).Seal(nonce, nonce, pt, ad), nil
}

func aeadOpen(mk, ad, ct []byte) ([]byte, error) {
	g := aeadFromKey(mk)
	if len(ct) < aeadNonceSize+g.Overhead() {
		return nil, errDecrypt
	}
	pt, err := g.Open(nil, ct[:aeadNonceSize], ct[aeadNonceSize:], ad)
	if err != nil {
		return nil, errDecrypt
	}
	return pt, nil
}

func aeadFromKey(mk []byte) cipher.AEAD {
	block, err := aes.NewCipher(kdf(nil, mk, "aead-key", 32))
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

func x25519Generate() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// x25519 computes DH(priv, pub); it rejects low-order points (all-zero output).
func x25519(priv, pub []byte) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return sk.ECDH(pk)
}

func ecdhPublic(priv []byte) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return sk.PublicKey().Bytes(), nil
}

func randRead(b []byte) (int, error) { return rand.Read(b) }

func zero(b []byte) { clear(b) }

// --- canonical binary encoding helpers ---

type encoder struct{ b []byte }

func (e *encoder) bytes(p []byte) *encoder { // u32 length prefix
	e.b = binary.BigEndian.AppendUint32(e.b, uint32(len(p)))
	e.b = append(e.b, p...)
	return e
}
func (e *encoder) str(s string) *encoder { return e.bytes([]byte(s)) }
func (e *encoder) u8(v uint8) *encoder   { e.b = append(e.b, v); return e }
func (e *encoder) u16(v uint16) *encoder { e.b = binary.BigEndian.AppendUint16(e.b, v); return e }
func (e *encoder) u32(v uint32) *encoder { e.b = binary.BigEndian.AppendUint32(e.b, v); return e }
func (e *encoder) u64(v uint64) *encoder { e.b = binary.BigEndian.AppendUint64(e.b, v); return e }
func (e *encoder) raw(p []byte) *encoder { e.b = append(e.b, p...); return e }

type decoder struct {
	b   []byte
	err bool
}

func (d *decoder) take(n int) []byte {
	if d.err || n < 0 || len(d.b) < n {
		d.err = true
		return nil
	}
	out := d.b[:n:n]
	d.b = d.b[n:]
	return out
}
func (d *decoder) u8() uint8 {
	if p := d.take(1); p != nil {
		return p[0]
	}
	return 0
}
func (d *decoder) u16() uint16 {
	if p := d.take(2); p != nil {
		return binary.BigEndian.Uint16(p)
	}
	return 0
}
func (d *decoder) u32() uint32 {
	if p := d.take(4); p != nil {
		return binary.BigEndian.Uint32(p)
	}
	return 0
}
func (d *decoder) u64() uint64 {
	if p := d.take(8); p != nil {
		return binary.BigEndian.Uint64(p)
	}
	return 0
}
func (d *decoder) bytes(max int) []byte {
	n := d.u32()
	if int64(n) > int64(max) {
		d.err = true
		return nil
	}
	p := d.take(int(n))
	if p == nil {
		return nil
	}
	return append([]byte(nil), p...)
}
func (d *decoder) done() bool { return !d.err && len(d.b) == 0 }
