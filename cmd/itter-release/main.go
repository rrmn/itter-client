// itter-release makes and checks the signatures on itter's releases. It is
// for whoever publishes releases; people who use itter never need it.
//
//	itter-release keygen <keyfile> <pubfile>   make a new release key
//	itter-release sign <keyfile> <file>        write <file>.sig
//	itter-release verify <pubfile> <file>      check <file>.sig
//	itter-release sums <out> <file>...         write a SHA256SUMS file
//	itter-release fingerprint <pubfile>        show a key's fingerprint
//
// The key file holds the private key, locked with a passphrase (Argon2id,
// AES-256-GCM), and stays on the publisher's computer. The public file holds
// the public key (base64): it goes into the program (internal/release/key.go)
// and into the README, with its fingerprint.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"

	"github.com/rrmn/itter-client/internal/pqc"
	"github.com/rrmn/itter-client/internal/release"
)

const keyKind = "itter-release-key/v1"

// keyFile is what the key file holds.
type keyFile struct {
	Kind   string `json:"kind"`
	Public []byte `json:"public"` // pqc.ReleaseKeyBytes
	KDF    kdf    `json:"kdf"`
	Nonce  []byte `json:"nonce"`
	Sealed []byte `json:"sealed"` // AES-256-GCM of the JSON of the pqc.SigningKey
}

type kdf struct {
	Name      string `json:"name"` // argon2id
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

func (k kdf) key(pass []byte) []byte {
	return argon2.IDKey(pass, k.Salt, k.Time, k.MemoryKiB, k.Threads, 32)
}

// aad binds the sealed key to the file's own description of it.
func (kf *keyFile) aad() []byte { return append([]byte(kf.Kind+"\n"), kf.Public...) }

// passphrase asks for the key's passphrase on the terminal.
// ITTER_RELEASE_PASSPHRASE is there for the tests.
var passphrase = func(prompt string) ([]byte, error) {
	if p := os.Getenv("ITTER_RELEASE_PASSPHRASE"); p != "" {
		return []byte(p), nil
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, errors.New("the passphrase has to be typed, and there is no terminal")
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	return p, err
}

func seal(sk *pqc.SigningKey, pub, pass []byte) (*keyFile, error) {
	kf := &keyFile{Kind: keyKind, Public: pub,
		KDF: kdf{Name: "argon2id", Salt: make([]byte, 16), Time: 3, MemoryKiB: 256 << 10, Threads: 4}}
	if _, err := rand.Read(kf.KDF.Salt); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(sk)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(kf.KDF.key(pass))
	if err != nil {
		return nil, err
	}
	kf.Nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(kf.Nonce); err != nil {
		return nil, err
	}
	kf.Sealed = gcm.Seal(nil, kf.Nonce, plain, kf.aad())
	return kf, nil
}

func (kf *keyFile) open(pass []byte) (*pqc.SigningKey, error) {
	if kf.KDF.Name != "argon2id" || len(kf.KDF.Salt) < 16 || kf.KDF.MemoryKiB < 64<<10 || kf.KDF.Time < 1 || kf.KDF.Threads < 1 {
		return nil, errors.New("the key file's lock is not one this tool makes")
	}
	gcm, err := newGCM(kf.KDF.key(pass))
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, kf.Nonce, kf.Sealed, kf.aad())
	if err != nil {
		return nil, errors.New("wrong passphrase (or a damaged key file)")
	}
	var sk pqc.SigningKey
	if err := json.Unmarshal(plain, &sk); err != nil {
		return nil, err
	}
	return &sk, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "itter-release:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: itter-release keygen|sign|verify|sums|fingerprint ...")
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "keygen":
		if len(rest) != 2 {
			return errors.New("usage: itter-release keygen <keyfile> <pubfile>")
		}
		return keygen(rest[0], rest[1])
	case "sign":
		if len(rest) != 2 {
			return errors.New("usage: itter-release sign <keyfile> <file>")
		}
		return sign(rest[0], rest[1])
	case "verify":
		if len(rest) != 2 {
			return errors.New("usage: itter-release verify <pubfile> <file>")
		}
		return verify(rest[0], rest[1])
	case "sums":
		if len(rest) < 2 {
			return errors.New("usage: itter-release sums <out> <file>...")
		}
		return sums(rest[0], rest[1:])
	case "fingerprint":
		if len(rest) != 1 {
			return errors.New("usage: itter-release fingerprint <pubfile>")
		}
		raw, _, err := readPub(rest[0])
		if err != nil {
			return err
		}
		fmt.Println(pqc.ReleaseKeyFingerprint(raw))
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func keygen(keyPath, pubPath string) error {
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists — a release key is made once; delete it yourself if you really mean to replace it", p)
		}
	}
	pass, err := passphrase("Passphrase for the new release key (12 characters or more): ")
	if err != nil {
		return err
	}
	if len(pass) < 12 {
		return errors.New("that passphrase is too short; nothing was made")
	}
	again, err := passphrase("The same passphrase again: ")
	if err != nil {
		return err
	}
	if !bytes.Equal(pass, again) {
		return errors.New("the two passphrases differ; nothing was made")
	}
	sk, vk, err := pqc.GenerateReleaseKey()
	if err != nil {
		return err
	}
	pub, err := vk.ReleaseKeyBytes()
	if err != nil {
		return err
	}
	kf, err := seal(sk, pub, pass)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := writeNew(keyPath, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := writeNew(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("release key made\n  private: %s (locked with your passphrase; keep a copy, and the passphrase, somewhere safe)\n  public:  %s\n  fingerprint: %s\n",
		keyPath, pubPath, pqc.ReleaseKeyFingerprint(pub))
	return nil
}

// writeNew writes a file that must not exist yet.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readKey(path string) (*pqc.SigningKey, *pqc.VerifyingKey, []byte, error) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, nil, nil, fmt.Errorf("%s can be read by others (mode %v) — chmod 600 it first", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil || kf.Kind != keyKind || len(kf.Sealed) == 0 {
		return nil, nil, nil, fmt.Errorf("%s is not an itter release key", path)
	}
	vk, err := pqc.ParseReleaseKey(kf.Public)
	if err != nil {
		return nil, nil, nil, err
	}
	fmt.Fprintf(os.Stderr, "release key %s\n", pqc.ReleaseKeyFingerprint(kf.Public))
	pass, err := passphrase("Passphrase of the release key: ")
	if err != nil {
		return nil, nil, nil, err
	}
	sk, err := kf.open(pass)
	if err != nil {
		return nil, nil, nil, err
	}
	if !sk.Matches(vk) {
		return nil, nil, nil, fmt.Errorf("%s is damaged: its private and public halves do not belong together", path)
	}
	return sk, vk, kf.Public, nil
}

func readPub(path string) ([]byte, *pqc.VerifyingKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, nil, fmt.Errorf("%s is not a release public key", path)
	}
	vk, err := pqc.ParseReleaseKey(raw)
	return raw, vk, err
}

func sign(keyPath, file string) error {
	sk, vk, pub, err := readKey(keyPath)
	if err != nil {
		return err
	}
	msg, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sig, err := sk.SignRelease(msg)
	if err != nil {
		return err
	}
	if err := vk.VerifyRelease(msg, sig); err != nil {
		return fmt.Errorf("the new signature does not check out: %v", err)
	}
	if err := os.WriteFile(file+".sig", sig, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s (key %s)\n", file, pqc.ReleaseKeyFingerprint(pub))
	return nil
}

func verify(pubPath, file string) error {
	raw, vk, err := readPub(pubPath)
	if err != nil {
		return err
	}
	msg, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(file + ".sig")
	if err != nil {
		return err
	}
	if err := vk.VerifyRelease(msg, sig); err != nil {
		return fmt.Errorf("%s: the signature does NOT check out", file)
	}
	fmt.Printf("%s: signed by the release key %s\n", file, pqc.ReleaseKeyFingerprint(raw))
	return nil
}

func sums(out string, files []string) error {
	s := release.Sums{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		name := filepath.Base(f)
		if _, dup := s[name]; dup {
			return fmt.Errorf("%s given twice", name)
		}
		s[name] = sha256.Sum256(data)
	}
	data := s.Format()
	if _, err := release.ParseSums(data); err != nil { // names the tools would refuse
		return err
	}
	if old, err := os.ReadFile(out); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return os.WriteFile(out, data, 0o644)
}
