package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	key, pub := filepath.Join(dir, "k", "release-key.json"), filepath.Join(dir, "release-key.pub")
	t.Setenv("ITTER_RELEASE_PASSPHRASE", "short")
	if err := run([]string{"keygen", key, pub}); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("short passphrase: %v", err)
	}
	t.Setenv("ITTER_RELEASE_PASSPHRASE", "correct horse battery staple")
	if err := run([]string{"keygen", key, pub}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(key); strings.Contains(string(raw), "ed25519") {
		t.Fatal("the private key is readable in the key file")
	}
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", fi.Mode().Perm())
	}
	if err := run([]string{"keygen", key, pub + "2"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("keygen over an existing key: %v", err)
	}

	a, b := filepath.Join(dir, "a.tar.gz"), filepath.Join(dir, "VERSION")
	os.WriteFile(a, []byte("archive"), 0o644)
	os.WriteFile(b, []byte("v0.1.0\n"), 0o644)
	sumsFile := filepath.Join(dir, "SHA256SUMS")
	if err := run([]string{"sums", sumsFile, a, b}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(sumsFile)
	if !strings.Contains(string(got), "  VERSION\n") || !strings.Contains(string(got), "  a.tar.gz\n") {
		t.Fatalf("SHA256SUMS: %q", got)
	}
	t.Setenv("ITTER_RELEASE_PASSPHRASE", "wrong horse battery staple")
	if err := run([]string{"sign", key, sumsFile}); err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("wrong passphrase: %v", err)
	}
	t.Setenv("ITTER_RELEASE_PASSPHRASE", "correct horse battery staple")
	if err := run([]string{"sign", key, sumsFile}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", pub, sumsFile}); err != nil {
		t.Fatal(err)
	}
	// Changed after signing: refused.
	os.WriteFile(sumsFile, append(got, '\n'), 0o644)
	if err := run([]string{"verify", pub, sumsFile}); err == nil {
		t.Fatal("changed file verified")
	}
	// A key file others can read is not used.
	os.Chmod(key, 0o644)
	if err := run([]string{"sign", key, sumsFile}); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("readable key file: %v", err)
	}
	if err := run([]string{"fingerprint", pub}); err != nil {
		t.Fatal(err)
	}
}
