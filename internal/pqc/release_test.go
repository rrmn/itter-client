package pqc

import (
	"bytes"
	"testing"
)

func TestReleaseSignature(t *testing.T) {
	sk, vk, err := GenerateReleaseKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("abc  itter_darwin_arm64.tar.gz\n")
	sig, err := sk.SignRelease(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != ReleaseSigSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), ReleaseSigSize)
	}
	if err := vk.VerifyRelease(msg, sig); err != nil {
		t.Fatalf("good signature refused: %v", err)
	}
	// Any change to the message or to any part of the signature is refused.
	if vk.VerifyRelease(append(bytes.Clone(msg), 'x'), sig) == nil {
		t.Fatal("signature accepted for another message")
	}
	for _, at := range []int{0, 64 + 100, FastSigSize + 100, len(sig) - 1} {
		bad := bytes.Clone(sig)
		bad[at] ^= 1
		if vk.VerifyRelease(msg, bad) == nil {
			t.Fatalf("signature with byte %d flipped accepted", at)
		}
	}
	// A signature made for another purpose with the same key is no release
	// signature, and the other way round.
	other, err := sk.SignFull(msg, "recover")
	if err != nil {
		t.Fatal(err)
	}
	if vk.VerifyRelease(msg, other) == nil {
		t.Fatal("a signature from another context passed as a release signature")
	}
	if vk.VerifyFull(msg, sig, "recover") == nil {
		t.Fatal("a release signature passed in another context")
	}

	enc, err := vk.ReleaseKeyBytes()
	if err != nil || len(enc) != ReleaseKeySize {
		t.Fatalf("encoding: %d bytes, %v", len(enc), err)
	}
	back, err := ParseReleaseKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.VerifyRelease(msg, sig); err != nil {
		t.Fatalf("decoded key refuses the signature: %v", err)
	}
	if _, err := ParseReleaseKey(enc[1:]); err == nil {
		t.Fatal("short key accepted")
	}
	if !sk.Matches(vk) {
		t.Fatal("key pair does not match itself")
	}
	_, vk2, _ := GenerateReleaseKey()
	if sk.Matches(vk2) {
		t.Fatal("key matched someone else's public key")
	}
	fp := ReleaseKeyFingerprint(enc)
	if len(fp) != 39 || fp != ReleaseKeyFingerprint(enc) {
		t.Fatalf("fingerprint %q", fp)
	}
}
