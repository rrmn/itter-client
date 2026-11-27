package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/rrmn/itter-client/internal/pqc"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v1.0.0", "v0.9.9", true},
		{"v0.10.0", "v0.9.0", true},
		{"v0.1.1", "v0.1.0", true},
		{"v0.1.0", "v0.1.0", false},
		{"v0.1.0", "v0.2.0", false},
		{"v0.1.0", "dev", true},
		{"dev", "v0.1.0", false},
		{"1.0.0", "v0.1.0", false},
		{"v1.0.0-rc1", "v0.1.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestSums(t *testing.T) {
	s := Sums{"b.tar.gz": sha256.Sum256([]byte("b")), "VERSION": sha256.Sum256([]byte("v1.2.3\n"))}
	back, err := ParseSums(s.Format())
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 || back["b.tar.gz"] != s["b.tar.gz"] {
		t.Fatalf("round trip: %v", back)
	}
	if !strings.HasPrefix(string(s.Format()), strings.Repeat("", 0)) || !strings.Contains(string(s.Format()), "  VERSION\n") {
		t.Fatalf("format: %q", s.Format())
	}
	if err := back.Check("b.tar.gz", []byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := back.Check("b.tar.gz", []byte("c")); !errors.Is(err, ErrMismatch) {
		t.Fatalf("changed file: %v", err)
	}
	if back.Check("other", nil) == nil {
		t.Fatal("a file not in the list passed")
	}
	for _, bad := range []string{
		"",
		"xyz  a\n",
		strings.Repeat("0", 64) + "  ../a\n",
		strings.Repeat("0", 64) + "  a\n" + strings.Repeat("1", 64) + "  a\n",
	} {
		if _, err := ParseSums([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// The binary-mode marker of sha256sum is fine too.
	if _, err := ParseSums([]byte(strings.Repeat("0", 64) + " *a\n")); err != nil {
		t.Fatal(err)
	}
}

// fakeRelease is a release as GitHub would serve it.
type fakeRelease struct {
	mu    sync.Mutex
	files map[string][]byte // name -> content, for the one release served
	hits  []string
}

func (f *fakeRelease) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits = append(f.hits, r.URL.Path)
	for _, prefix := range []string{"/releases/latest/download/", "/releases/download/v9.9.9/"} {
		if name, ok := strings.CutPrefix(r.URL.Path, prefix); ok {
			if data, ok := f.files[name]; ok {
				w.Write(data)
				return
			}
		}
	}
	http.NotFound(w, r)
}

func archive(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write(content)
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

// newFake makes a signed release v9.9.9 whose program, when run with
// "version", says so.
func newFake(t *testing.T) (*fakeRelease, *pqc.SigningKey, *pqc.VerifyingKey, []byte) {
	t.Helper()
	sk, vk, err := pqc.GenerateReleaseKey()
	if err != nil {
		t.Fatal(err)
	}
	prog := []byte("#!/bin/sh\necho 'itter v9.9.9 (test)'\n")
	files := map[string][]byte{
		VersionFile:                             []byte("v9.9.9\n"),
		AssetName(runtime.GOOS, runtime.GOARCH): archive(t, "itter", prog),
		InstallFile:                             []byte("#!/bin/sh\n"),
	}
	sums := Sums{}
	for n, d := range files {
		sums[n] = sha256.Sum256(d)
	}
	files[SumsFile] = sums.Format()
	sig, err := sk.SignRelease(files[SumsFile])
	if err != nil {
		t.Fatal(err)
	}
	files[SigFile] = sig
	return &fakeRelease{files: files}, sk, vk, prog
}

func TestFetchAndReplace(t *testing.T) {
	fake, sk, vk, prog := newFake(t)
	srv := httptest.NewServer(fake)
	defer srv.Close()
	f := &Fetcher{Base: srv.URL + "/releases", Key: vk}
	ctx := context.Background()

	r, err := f.Latest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "v9.9.9" {
		t.Fatalf("version %q", r.Version)
	}
	if _, err := f.Get(ctx, "v9.9.9"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(ctx, "9.9.9"); err == nil {
		t.Fatal("a version without v was asked for")
	}
	bin, err := f.Binary(ctx, r, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bin, prog) {
		t.Fatal("wrong program out of the archive")
	}
	if _, err := f.Binary(ctx, r, "plan9", "mips"); err == nil {
		t.Fatal("a system without a build got one")
	}

	// Installing: the old program is replaced, through a symlink too.
	dir := t.TempDir()
	path := filepath.Join(dir, "itter")
	os.WriteFile(path, []byte("old"), 0o755)
	if err := Replace(path, bin, r.Version); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, prog) {
		t.Fatal("program not replaced")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".itter-update-*"))
	if len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	// A program that does not run, or calls itself something else, does not
	// replace anything.
	os.WriteFile(path, []byte("old"), 0o755)
	if err := Replace(path, []byte("\x00not a program"), "v9.9.9"); err == nil {
		t.Fatal("a broken program was installed")
	}
	if err := Replace(path, bin, "v9.9.10"); err == nil {
		t.Fatal("a program with another version was installed")
	}
	if got, _ := os.ReadFile(path); string(got) != "old" {
		t.Fatal("the old program was touched")
	}

	// Tampering: each of these must be refused.
	tamper := func(name string, change func([]byte) []byte) {
		t.Helper()
		fake.mu.Lock()
		old := fake.files[name]
		fake.files[name] = change(bytes.Clone(old))
		fake.mu.Unlock()
		defer func() { fake.mu.Lock(); fake.files[name] = old; fake.mu.Unlock() }()
		r, err := f.Latest(ctx)
		if err == nil {
			_, err = f.Binary(ctx, r, runtime.GOOS, runtime.GOARCH)
		}
		if err == nil {
			t.Fatalf("tampered %s accepted", name)
		}
	}
	tamper(SumsFile, func(b []byte) []byte { b[0] ^= 1; return b })
	tamper(SigFile, func(b []byte) []byte { b[len(b)-1] ^= 1; return b })
	tamper(VersionFile, func([]byte) []byte { return []byte("v10.0.0\n") })
	tamper(AssetName(runtime.GOOS, runtime.GOARCH), func(b []byte) []byte { return archive(t, "itter", []byte("evil")) })

	// Signed by another key: refused.
	sk2, _, _ := pqc.GenerateReleaseKey()
	tamper(SigFile, func([]byte) []byte { s, _ := sk2.SignRelease(fake.files[SumsFile]); return s })
	_ = sk

	// The program's own release key did not sign this test release.
	if _, err := (&Fetcher{Base: srv.URL + "/releases"}).Latest(ctx); !errors.Is(err, ErrSignature) {
		t.Fatalf("release signed with another key: %v", err)
	}
	// A build without a release key cannot check anything.
	saved := releaseKey
	releaseKey = ""
	defer func() { releaseKey = saved }()
	if _, err := (&Fetcher{Base: srv.URL + "/releases"}).Latest(ctx); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
}

func TestExtract(t *testing.T) {
	if _, err := Extract(archive(t, "./itter", []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(archive(t, "other", []byte("x"))); err == nil {
		t.Fatal("found a program that is not there")
	}
	if _, err := Extract([]byte("not gzip")); err == nil {
		t.Fatal("not an archive, no error")
	}
}

func TestEmbeddedKey(t *testing.T) {
	vk, raw, err := PublicKey()
	if err != nil || vk == nil {
		t.Fatalf("the release key in the program does not parse: %v", err)
	}
	if got := pqc.ReleaseKeyFingerprint(raw); got != ReleaseKeyFingerprint || Fingerprint() != got {
		t.Fatalf("fingerprint %q, documented %q", got, ReleaseKeyFingerprint)
	}
}
