// Package release finds, checks and installs releases of the itter program.
//
// A release on GitHub carries one archive per system, a VERSION file, and a
// SHA256SUMS file that lists all of them. SHA256SUMS is signed with the
// release key (pqc.SignRelease: Ed25519 + ML-DSA-87 + SLH-DSA). The program
// carries the public half of that key, so an update only gets installed if
// the release key signed it, whatever GitHub, HTTPS or anyone in between
// does. Only the very first download has to be taken on trust; see the
// README for how to check that one by hand.
package release

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rrmn/itter-client/internal/pqc"
)

// Repo is the GitHub repository releases are published in.
const Repo = "rrmn/itter-client"

// DefaultBase is where releases are downloaded from.
const DefaultBase = "https://github.com/" + Repo + "/releases"

// The files every release has besides the archives.
const (
	SumsFile    = "SHA256SUMS"
	SigFile     = "SHA256SUMS.sig"
	VersionFile = "VERSION"
	InstallFile = "install.sh"
	// BinaryName is the program inside each archive.
	BinaryName = "itter"
)

// Size limits for what is downloaded.
const (
	maxSmall   = 64 << 10  // SHA256SUMS, its signature, VERSION
	maxArchive = 64 << 20  // one archive
	maxBinary  = 128 << 20 // the program inside it
)

// Platforms are the systems releases are built for.
var Platforms = []struct{ OS, Arch string }{
	{"darwin", "arm64"}, {"darwin", "amd64"}, {"linux", "amd64"}, {"linux", "arm64"},
}

// AssetName is the archive for one system.
func AssetName(goos, goarch string) string { return "itter_" + goos + "_" + goarch + ".tar.gz" }

var versionRE = regexp.MustCompile(`^v(\d{1,6})\.(\d{1,6})\.(\d{1,6})$`)

// ValidVersion reports whether v is a release version (vMAJOR.MINOR.PATCH).
func ValidVersion(v string) bool { return versionRE.MatchString(v) }

// Newer reports whether version a is newer than version b. Anything that is
// not a release version (such as "dev") counts as older than every release.
func Newer(a, b string) bool {
	pa, pb := parseVersion(a), parseVersion(b)
	if pa == nil {
		return false
	}
	if pb == nil {
		return true
	}
	for i := range 3 {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseVersion(v string) []int {
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return nil
	}
	out := make([]int, 3)
	for i := range 3 {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}

// --- SHA256SUMS ---

// Sums maps file names to their SHA-256.
type Sums map[string][32]byte

var sumsLine = regexp.MustCompile(`^([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)$`)

// ParseSums reads a SHA256SUMS file as sha256sum writes it.
func ParseSums(b []byte) (Sums, error) {
	s := Sums{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		m := sumsLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("%s: bad line %q", SumsFile, line)
		}
		if _, dup := s[m[2]]; dup {
			return nil, fmt.Errorf("%s: %s is listed twice", SumsFile, m[2])
		}
		var h [32]byte
		hex.Decode(h[:], []byte(m[1]))
		s[m[2]] = h
	}
	if len(s) == 0 {
		return nil, fmt.Errorf("%s is empty", SumsFile)
	}
	return s, sc.Err()
}

// Format writes the file back, sorted by name, the way sha256sum would.
func (s Sums) Format() []byte {
	names := make([]string, 0, len(s))
	for n := range s {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, n := range names {
		h := s[n]
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h[:]), n)
	}
	return b.Bytes()
}

// ErrMismatch means a file is not the one SHA256SUMS lists.
var ErrMismatch = errors.New("the download does not match the signed checksums")

// Check makes sure data is the file listed under name.
func (s Sums) Check(name string, data []byte) error {
	want, ok := s[name]
	if !ok {
		return fmt.Errorf("%s is not part of this release", name)
	}
	if sha256.Sum256(data) != want {
		return fmt.Errorf("%s: %w", name, ErrMismatch)
	}
	return nil
}

// --- the release key ---

// ErrNoKey means this build of the program carries no release key (a build
// made by hand rather than a release), so it cannot check updates.
var ErrNoKey = errors.New("this build of itter has no release key, so it cannot check updates — install a release")

// ErrSignature means SHA256SUMS is not signed by the release key.
var ErrSignature = errors.New("the release is not signed with itter's release key")

// PublicKey returns the release key this program carries and its encoding.
func PublicKey() (*pqc.VerifyingKey, []byte, error) {
	if releaseKey == "" {
		return nil, nil, ErrNoKey
	}
	raw, err := base64.StdEncoding.DecodeString(releaseKey)
	if err != nil {
		return nil, nil, err
	}
	vk, err := pqc.ParseReleaseKey(raw)
	return vk, raw, err
}

// Fingerprint is the fingerprint of the release key this program carries, ""
// if it carries none.
func Fingerprint() string {
	_, raw, err := PublicKey()
	if err != nil {
		return ""
	}
	return pqc.ReleaseKeyFingerprint(raw)
}

// --- downloading ---

// Fetcher downloads releases and checks them.
type Fetcher struct {
	Base   string            // DefaultBase unless a test says otherwise
	Client *http.Client      // nil: a client with sensible timeouts
	Key    *pqc.VerifyingKey // nil: the key this program carries
	UA     string            // User-Agent
}

// Release is a release whose SHA256SUMS checked out.
type Release struct {
	Version string
	Sums    Sums
	dir     string // where its files are downloaded from
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (f *Fetcher) base() string {
	if f.Base != "" {
		return strings.TrimRight(f.Base, "/")
	}
	return DefaultBase
}

// get downloads one file, at most limit bytes of it.
func (f *Fetcher) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if f.UA != "" {
		req.Header.Set("User-Agent", f.UA)
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%s: not found", url)
		}
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than expected", url)
	}
	return data, nil
}

// Latest returns the newest release, checked.
func (f *Fetcher) Latest(ctx context.Context) (*Release, error) {
	return f.fetch(ctx, f.base()+"/latest/download")
}

// Get returns the release with the given version, checked.
func (f *Fetcher) Get(ctx context.Context, version string) (*Release, error) {
	if !ValidVersion(version) {
		return nil, fmt.Errorf("%q is not a release version (like v1.2.3)", version)
	}
	return f.fetch(ctx, f.base()+"/download/"+version)
}

func (f *Fetcher) fetch(ctx context.Context, dir string) (*Release, error) {
	key := f.Key
	if key == nil {
		var err error
		if key, _, err = PublicKey(); err != nil {
			return nil, err
		}
	}
	sums, err := f.get(ctx, dir+"/"+SumsFile, maxSmall)
	if err != nil {
		return nil, err
	}
	sig, err := f.get(ctx, dir+"/"+SigFile, maxSmall)
	if err != nil {
		return nil, err
	}
	if key.VerifyRelease(sums, sig) != nil {
		return nil, ErrSignature
	}
	parsed, err := ParseSums(sums)
	if err != nil {
		return nil, err
	}
	ver, err := f.get(ctx, dir+"/"+VersionFile, maxSmall)
	if err != nil {
		return nil, err
	}
	if err := parsed.Check(VersionFile, ver); err != nil {
		return nil, err
	}
	v := strings.TrimSpace(string(ver))
	if !ValidVersion(v) {
		return nil, fmt.Errorf("the release names itself %q, which is not a version", v)
	}
	return &Release{Version: v, Sums: parsed, dir: dir}, nil
}

// Binary downloads the program for one system from r and checks it.
func (f *Fetcher) Binary(ctx context.Context, r *Release, goos, goarch string) ([]byte, error) {
	name := AssetName(goos, goarch)
	if _, ok := r.Sums[name]; !ok {
		return nil, fmt.Errorf("release %s has no build for %s/%s", r.Version, goos, goarch)
	}
	archive, err := f.get(ctx, r.dir+"/"+name, maxArchive)
	if err != nil {
		return nil, err
	}
	if err := r.Sums.Check(name, archive); err != nil {
		return nil, err
	}
	return Extract(archive)
}

// Extract takes the program out of a release archive.
func Extract(archive []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("the archive has no %s in it", BinaryName)
		}
		if err != nil {
			return nil, err
		}
		if strings.TrimPrefix(h.Name, "./") != BinaryName || h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size > maxBinary {
			return nil, errors.New("the program in the archive is too large")
		}
		return io.ReadAll(io.LimitReader(tr, maxBinary))
	}
}

// --- installing ---

// ErrNotWritable means the program's file cannot be replaced by this user.
type ErrNotWritable struct{ Path string }

func (e *ErrNotWritable) Error() string {
	return fmt.Sprintf("cannot replace %s: no permission (it was installed by another user — try `sudo itter update`)", e.Path)
}

// Executable is where the running program lives, symlinks followed.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// Replace puts binary in place of the program at path. The new program is
// written next to the old one first and run once ("version"), so a broken
// download never replaces a working program; the switch itself is a rename.
func Replace(path string, binary []byte, wantVersion string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".itter-update-*")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return &ErrNotWritable{path}
		}
		return err
	}
	name := tmp.Name()
	done := false
	defer func() {
		if !done {
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, "version").Output()
	if err != nil {
		return fmt.Errorf("the new program does not start on this computer (%v); nothing was changed", err)
	}
	if wantVersion != "" && !strings.Contains(string(out), wantVersion) {
		return fmt.Errorf("the new program calls itself %q, not %s; nothing was changed", strings.TrimSpace(string(out)), wantVersion)
	}
	if err := os.Rename(name, path); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return &ErrNotWritable{path}
		}
		return err
	}
	done = true
	return nil
}
