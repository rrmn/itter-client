package pqc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func envParts(t *testing.T, w *WireMsg) (hdr, ct []byte) {
	t.Helper()
	ep, err := ParseEnvelope(w)
	if err != nil {
		t.Fatal(err)
	}
	hl := int(binary.BigEndian.Uint32(ep.Env))
	return ep.Env[4 : 4+hl], ep.Env[4+hl:]
}

// If ratchet state is rolled back (crash before saving, restored backup, two
// processes), the same message key is derived twice. That must not become
// AES-GCM nonce reuse.
func TestStateRollbackDoesNotReuseNonce(t *testing.T) {
	a, b := start(t, true)
	expect(t, b, send(t, a, "hello"), "hello")
	expect(t, a, send(t, b, "hey"), "hey")

	saved := mustJSON(t, a.sess)
	w1 := send(t, a, "attack at dawn!!")
	var rolled Session
	if err := json.Unmarshal(saved, &rolled); err != nil {
		t.Fatal(err)
	}
	a.sess = &rolled
	w2 := send(t, a, "retreat at dusk!")

	h1, c1 := envParts(t, w1)
	h2, c2 := envParts(t, w2)
	if !bytes.Equal(h1, h2) {
		t.Fatal("test premise broken: rollback should reproduce the same header (same message key)")
	}
	if bytes.Equal(c1[:aeadNonceSize], c2[:aeadNonceSize]) {
		t.Fatal("same key AND same nonce for two different plaintexts")
	}
	p1, p2 := pad([]byte("attack at dawn!!")), pad([]byte("retreat at dusk!"))
	same := 0
	for i := 0; i < 20; i++ {
		if c1[aeadNonceSize+i]^c2[aeadNonceSize+i] == p1[i]^p2[i] {
			same++
		}
	}
	if same == 20 {
		t.Fatal("keystream reuse: XOR of ciphertexts equals XOR of plaintexts")
	}
	// The receiver takes the first and recognises the second as a reuse.
	expect(t, b, w1, "attack at dawn!!")
	if _, err := b.receive(t, w2); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second message under the same key: got %v, want ErrDuplicate", err)
	}
}

func TestDuplicatesAreToldApartFromGarbage(t *testing.T) {
	a, b := start(t, true)
	expect(t, b, send(t, a, "one"), "one")
	expect(t, a, send(t, b, "two"), "two")
	old := send(t, a, "three") // a's chain #2
	expect(t, b, old, "three")
	if _, err := b.receive(t, old); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay in the current chain: got %v, want ErrDuplicate", err)
	}
	// Move both sides on by a full DH ratchet round, then replay again.
	expect(t, a, send(t, b, "four"), "four")
	expect(t, b, send(t, a, "five"), "five")
	if _, err := b.receive(t, old); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay from a finished chain: got %v, want ErrDuplicate", err)
	}
	// Garbage is not a duplicate.
	w := send(t, a, "six")
	ep, _ := ParseEnvelope(w)
	ep.Env[len(ep.Env)-1] ^= 1
	if _, err := b.sess.Decrypt(ep.Env); !errors.Is(err, ErrDecrypt) || errors.Is(err, ErrDuplicate) {
		t.Fatalf("tampered message: got %v, want ErrDecrypt", err)
	}
	expect(t, b, w, "six")
}

// A peer that sends an invalid KEM key (or otherwise breaks the PQ protocol)
// freezes that PQ ratchet. It must not be able to stop messages.
func TestInvalidPeerKEMKeyOnlyStallsThePQRatchet(t *testing.T) {
	a, b := start(t, true)
	expect(t, b, send(t, a, "hi"), "hi")
	expect(t, a, send(t, b, "yo"), "yo")

	bad := bytes.Repeat([]byte{0xFF}, kemMLKEM768.ekSize()) // coefficients >= q
	b.sess.PQ1.St, b.sess.PQ1.EK, b.sess.PQ1.Dec = stEkReceived, bad, nil
	for i := 0; i < 5; i++ {
		expect(t, a, send(t, b, "still talking"), "still talking")
		expect(t, b, send(t, a, "yes"), "yes")
	}

	// A key that is authenticated but malformed freezes the ratchet as soon
	// as it arrives, and says so.
	a3, b3 := start(t, true)
	expect(t, b3, send(t, a3, "hi"), "hi")
	a3.sess.PQ1.Enc = newRSEncoder(append(bad, a3.sess.PQ1.Auth.mac(braidMLKEM, "ek", a3.sess.PQ1.Ep, bad)...), braidMLKEM.chunk)
	for i := 0; i < 16; i++ { // one mixed reconstruction first (b3 already holds a chunk of the real key)
		expect(t, a3, send(t, b3, "ping"), "ping")
		expect(t, b3, send(t, a3, "pong"), "pong")
	}
	if !strings.Contains(b3.sess.PQStalled(), "ML-KEM") {
		t.Fatalf("an invalid key should freeze the ML-KEM ratchet visibly, got %q", b3.sess.PQStalled())
	}

	// Persistent MAC failures after a valid AEAD: messages are delivered, and
	// after a few attempts the ratchet is frozen.
	a2, b2 := start(t, true)
	expect(t, b2, send(t, a2, "hi"), "hi")
	a2.sess.PQ2.Auth.Mac[0] ^= 1 // a2 will MAC its FrodoKEM key with the wrong key
	a2.sess.PQ2.Enc, a2.sess.PQ2.St, a2.sess.PQ2.DK = nil, stKeysUnsampled, nil
	for i := 0; i < 5*maxBraidFails; i++ {
		expect(t, a2, send(t, b2, "ping"), "ping")
		expect(t, b2, send(t, a2, "pong"), "pong")
	}
	if b2.sess.PQStalled() == "" {
		t.Fatal("expected the FrodoKEM ratchet to be reported as stalled")
	}
	if ml, _ := b2.sess.PQEpochs(); ml < 1 {
		t.Fatal("the healthy ML-KEM ratchet should keep advancing")
	}
}

// If the peer restarts an epoch (it lost state after sending some chunks),
// chunks of two different keys get mixed. That costs one failed
// reconstruction; then the ratchet carries on by itself.
func TestBraidRecoversFromMixedChunks(t *testing.T) {
	a, b := start(t, true)
	expect(t, b, send(t, a, "hi"), "hi")
	expect(t, a, send(t, b, "yo"), "yo")
	// a has sent two chunks of its FrodoKEM key. Now it "forgets" the key
	// pair and samples a new one for the same epoch.
	a.sess.PQ2.St, a.sess.PQ2.Enc, a.sess.PQ2.DK = stKeysUnsampled, nil, nil
	for i := 0; i < 40; i++ {
		expect(t, b, send(t, a, "ping"), "ping")
		expect(t, a, send(t, b, "pong"), "pong")
	}
	if st := a.sess.PQStalled() + b.sess.PQStalled(); st != "" {
		t.Fatalf("stalled: %s", st)
	}
	if _, fr := b.sess.PQEpochs(); fr < 3 {
		t.Fatalf("the FrodoKEM ratchet did not recover: %d steps", fr)
	}
}

// A message that is overtaken by several ratchet steps still decrypts; one
// that is hopelessly late fails cleanly.
func TestLateMessages(t *testing.T) {
	a, b := start(t, true)
	expect(t, b, send(t, a, "hi"), "hi")
	expect(t, a, send(t, b, "yo"), "yo")
	late := send(t, a, "overtaken")
	rounds := func(n int) {
		for i := 0; i < n; i++ {
			expect(t, b, send(t, a, "ping"), "ping")
			expect(t, a, send(t, b, "pong"), "pong")
		}
	}
	rounds(14) // about two PQ steps in each ratchet
	expect(t, b, late, "overtaken")
	veryLate := send(t, a, "far too late")
	rounds(120)
	before := mustJSON(t, b.sess)
	if _, err := b.receive(t, veryLate); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
	if !bytes.Equal(before, mustJSON(t, b.sess)) {
		t.Fatal("a message that came too late changed the session")
	}
}

func TestFingerprintIs256Bits(t *testing.T) {
	fixtures(t)
	fp := Fingerprint(alice.id.Pub.Encode())
	if len(strings.ReplaceAll(fp, " ", "")) != 64 || fp == Fingerprint(bob.id.Pub.Encode()) {
		t.Fatalf("fingerprint %q", fp)
	}
}
