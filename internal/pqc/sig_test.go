package pqc

import "testing"

func TestCompositeSignatures(t *testing.T) {
	fixtures(t)
	vk := &alice.id.Pub.VerifyingKey
	msg := []byte("bind me")
	full, err := alice.id.Sign.SignFull(msg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != FullSigSize {
		t.Fatalf("full signature is %d bytes, want %d", len(full), FullSigSize)
	}
	if err := vk.VerifyFull(msg, full, "test"); err != nil {
		t.Fatal(err)
	}
	if vk.VerifyFull(msg, full, "other-context") == nil {
		t.Fatal("signature verified under the wrong context")
	}
	if vk.VerifyFull([]byte("bind mE"), full, "test") == nil {
		t.Fatal("signature verified for the wrong message")
	}
	// Breaking any single component must break the whole signature.
	for _, off := range []int{0, ed25519SigSize + 10, FastSigSize + 100} {
		bad := append([]byte(nil), full...)
		bad[off] ^= 0x80
		if vk.VerifyFull(msg, bad, "test") == nil {
			t.Fatalf("tampering at offset %d went unnoticed", off)
		}
	}
	if vk.VerifyFull(msg, full[:FastSigSize], "test") == nil {
		t.Fatal("a signature without its hash-based part must not pass")
	}
	if (&bob.id.Pub.VerifyingKey).VerifyFull(msg, full, "test") == nil {
		t.Fatal("verified with the wrong key")
	}
}

func TestIdentityEncoding(t *testing.T) {
	fixtures(t)
	enc := alice.id.Pub.Encode()
	k, err := DecodeIdentityKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(k.Encode()) != string(enc) {
		t.Fatal("identity encoding does not round-trip")
	}
	if _, err := DecodeIdentityKey(enc[:len(enc)-1]); err == nil {
		t.Fatal("truncated identity accepted")
	}
	sn1 := SafetyNumber(alice.id.Pub.Encode(), bob.id.Pub.Encode())
	sn2 := SafetyNumber(bob.id.Pub.Encode(), alice.id.Pub.Encode())
	if sn1 != sn2 || len(sn1) != 71 {
		t.Fatalf("safety number not symmetric or wrong length: %q", sn1)
	}
}
