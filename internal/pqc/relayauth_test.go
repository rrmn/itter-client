package pqc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSessionAgreement(t *testing.T) {
	offer, err := NewSessionOffer()
	if err != nil {
		t.Fatal(err)
	}
	if len(offer.Public()) != SessionOfferSize() {
		t.Fatalf("offer is %d bytes, want %d", len(offer.Public()), SessionOfferSize())
	}
	bind := []byte("alice/device/ticket")
	answer, relaySecret, err := AnswerSession(offer.Public(), bind)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := offer.Open(answer, bind)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != SessionKeySize || !bytes.Equal(secret, relaySecret) {
		t.Fatal("the two sides did not arrive at the same secret")
	}

	t.Run("another purpose, another secret", func(t *testing.T) {
		other, err := offer.Open(answer, []byte("bob/device/ticket"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(other, secret) {
			t.Fatal("the secret does not depend on what the session is for")
		}
	})

	t.Run("an answer that was touched gives another secret or none", func(t *testing.T) {
		for _, at := range []int{4, 40, 4 + 32 + 4 + 500, len(answer) - 1} {
			bad := bytes.Clone(answer)
			bad[at] ^= 1
			got, err := offer.Open(bad, bind)
			if err == nil && bytes.Equal(got, secret) {
				t.Fatalf("flipping byte %d went unnoticed", at)
			}
		}
		if _, err := offer.Open(answer[:len(answer)-1], bind); err == nil {
			t.Fatal("a short answer was accepted")
		}
		if _, err := offer.Open(append(bytes.Clone(answer), 0), bind); err == nil {
			t.Fatal("an answer with something after it was accepted")
		}
	})

	t.Run("each answer has its own secret", func(t *testing.T) {
		answer2, secret2, err := AnswerSession(offer.Public(), bind)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(answer2, answer) || bytes.Equal(secret2, relaySecret) {
			t.Fatal("two answers to one offer are the same")
		}
	})

	t.Run("offers that are not offers", func(t *testing.T) {
		pub := offer.Public()
		lowOrder := bytes.Clone(pub)
		clear(lowOrder[4 : 4+32]) // the all-zero X25519 point
		for name, bad := range map[string][]byte{
			"empty":       nil,
			"short":       pub[:len(pub)-1],
			"long":        append(bytes.Clone(pub), 0),
			"low order":   lowOrder,
			"wrong sizes": (&encoder{}).bytes(pub[4:36]).bytes([]byte("x")).bytes([]byte("y")).b,
		} {
			if _, _, err := AnswerSession(bad, bind); err == nil {
				t.Errorf("%s: answered", name)
			}
		}
	})

	t.Run("the key the relay hands out", func(t *testing.T) {
		key := bytes.Repeat([]byte{7}, SessionKeySize)
		box, err := WrapSessionKey(relaySecret, []byte("ticket"), key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnwrapSessionKey(secret, []byte("ticket"), box)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("unwrap: %x, %v", got, err)
		}
		if _, err := UnwrapSessionKey(secret, []byte("another ticket"), box); err == nil {
			t.Fatal("opened for another ticket")
		}
		wrong := bytes.Clone(secret)
		wrong[0] ^= 1
		if _, err := UnwrapSessionKey(wrong, []byte("ticket"), box); err == nil {
			t.Fatal("opened with another secret")
		}
		if _, err := WrapSessionKey(relaySecret, nil, []byte("short")); err == nil {
			t.Fatal("wrapped a key of the wrong size")
		}
	})
}

func TestRecoveryKey(t *testing.T) {
	code := bytes.Repeat([]byte{0x42}, RecoveryCodeSize)
	pub, err := RecoveryPublic(code)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != RecoveryPublicSize {
		t.Fatalf("public key is %d bytes", len(pub))
	}
	// The key must never change for a given code: relays store it, and people
	// keep the code on paper for years. If this fails, the SLH-DSA library
	// changed how it turns seeds into keys.
	const want = "021c8855b816849bce5a172e0792c132f9c403ed1f29cca51b73113f12e200f259dd007683b0c72ccce957ccdc438ca192d716dd9328967f25a156461a52d5bc"
	if got := hex.EncodeToString(pub); got != want {
		t.Fatalf("the recovery key of a known code changed:\n got %s\nwant %s", got, want)
	}
	again, _ := RecoveryPublic(code)
	if !bytes.Equal(again, pub) {
		t.Fatal("the same code gave two keys")
	}

	msg := []byte("release alice")
	sig, err := RecoverySign(code, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != RecoverySigSize {
		t.Fatalf("signature is %d bytes", len(sig))
	}
	if err := RecoveryVerify(pub, msg, sig); err != nil {
		t.Fatal(err)
	}
	if RecoveryVerify(pub, []byte("release bob"), sig) == nil {
		t.Fatal("verified for another message")
	}
	bad := bytes.Clone(sig)
	bad[100] ^= 1
	if RecoveryVerify(pub, msg, bad) == nil {
		t.Fatal("a touched signature verified")
	}

	other := bytes.Repeat([]byte{0x43}, RecoveryCodeSize)
	otherPub, _ := RecoveryPublic(other)
	if bytes.Equal(otherPub, pub) {
		t.Fatal("two codes, one key")
	}
	if RecoveryVerify(otherPub, msg, sig) == nil {
		t.Fatal("verified under another code's key")
	}
	otherSig, _ := RecoverySign(other, msg)
	if RecoveryVerify(pub, msg, otherSig) == nil {
		t.Fatal("another code's signature verified")
	}

	for name, c := range map[string][]byte{"short": code[:31], "long": append(bytes.Clone(code), 1), "none": nil} {
		if _, err := RecoveryPublic(c); err == nil {
			t.Errorf("%s code: got a key", name)
		}
		if _, err := RecoverySign(c, msg); err == nil {
			t.Errorf("%s code: got a signature", name)
		}
	}
	if RecoveryVerify(pub[:63], msg, sig) == nil || RecoveryVerify(pub, msg, sig[:len(sig)-1]) == nil {
		t.Fatal("wrong sizes verified")
	}
}
