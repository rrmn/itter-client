package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/muesli/cancelreader"
	"golang.org/x/crypto/ssh"

	"github.com/rrmn/itter-client/internal/relay"
)

func TestMarkerScanner(t *testing.T) {
	stream := "itter> " + markerStart + "dm;@bob\a" + "after" + markerStart + "dm\a" + "\x1b[31mred\x1b[0m"
	wantText := "itter> after\x1b[31mred\x1b[0m"
	wantMarkers := []string{"dm;@bob", "dm"}
	// In one piece, and split in two at every possible place.
	for cut := 0; cut <= len(stream); cut++ {
		var s markerScanner
		var text bytes.Buffer
		var markers []string
		feed := func(b string) {
			s.feed([]byte(b), func(p []byte) { text.Write(p) }, func(m string) { markers = append(markers, m) })
		}
		feed(stream[:cut])
		feed(stream[cut:])
		s.flush(func(p []byte) { text.Write(p) })
		if text.String() != wantText || strings.Join(markers, "|") != strings.Join(wantMarkers, "|") {
			t.Fatalf("cut at %d: text %q markers %q", cut, text.String(), markers)
		}
	}
	// Something that only starts like a marker is text, once it is clear.
	var s markerScanner
	var text bytes.Buffer
	s.feed([]byte("a\x1b]77"), func(p []byte) { text.Write(p) }, func(string) { t.Fatal("marker") })
	if text.String() != "a" {
		t.Fatalf("held back too little: %q", text.String())
	}
	s.feed([]byte("x;title\a"), func(p []byte) { text.Write(p) }, func(string) { t.Fatal("marker") })
	if text.String() != "a\x1b]77x;title\a" {
		t.Fatalf("got %q", text.String())
	}
	// A marker that never ends is text after all.
	text.Reset()
	long := markerStart + strings.Repeat("x", markerMax+10)
	s.feed([]byte(long), func(p []byte) { text.Write(p) }, func(string) { t.Fatal("marker") })
	if text.String() != long {
		t.Fatalf("long: %q", text.String())
	}
}

func TestParseMarker(t *testing.T) {
	for _, c := range []struct {
		in, target string
		ok         bool
	}{
		{"dm", "", true}, {"dm;@bob", "bob", true}, {"dm;bob", "bob", true},
		{"dm;@b o b", "", true}, {"rm -rf", "", false}, {"", "", false},
	} {
		if target, ok := parseMarker(c.in); target != c.target || ok != c.ok {
			t.Errorf("parseMarker(%q) = %q, %v", c.in, target, ok)
		}
	}
}

func TestANSITracker(t *testing.T) {
	for _, c := range []struct {
		in   string
		safe bool
	}{
		{"plain text", true},
		{"\x1b", false},
		{"\x1b[31", false},
		{"\x1b[31m", true},
		{"\x1b]0;title", false},
		{"\x1b]0;title\a", true},
		{"\x1b]0;title\x1b", false},
		{"\x1b]0;title\x1b\\", true},
		{"\x1bP1;2", false},
		{"\x1b(", false},
		{"\x1b(B", true},
		{"\xc3", false},
		{"\xc3\xa9", true},
		{"\xe2\x82", false},
		{"\xe2\x82\xac", true},
		{"\x1b7", true},
	} {
		var a ansiTracker
		a.feed([]byte(c.in))
		if a.safe() != c.safe {
			t.Errorf("%q: safe=%v", c.in, a.safe())
		}
	}
}

func TestClientVersion(t *testing.T) {
	saved := version
	defer func() { version = saved }()
	version = "v1.2.3"
	if got := clientVersion(); got != "SSH-2.0-itterclient_v1.2.3" {
		t.Fatalf("%q", got)
	}
	version = "dev-build x"
	if got := clientVersion(); strings.ContainsAny(got[len("SSH-2.0-"):], "- ") {
		t.Fatalf("%q has characters SSH does not allow there", got)
	}
}

// syncBuffer is a bytes.Buffer for several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeKeys is a keyboard that can be stopped, like the real one.
type fakeKeys struct {
	typed  chan []byte
	cancel chan struct{}
	once   sync.Once
}

func (f *fakeKeys) Read(p []byte) (int, error) {
	select {
	case b := <-f.typed:
		return copy(p, b), nil
	case <-f.cancel:
		return 0, cancelreader.ErrCanceled
	}
}
func (f *fakeKeys) Cancel() bool { f.once.Do(func() { close(f.cancel) }); return true }
func (f *fakeKeys) Close() error { return nil }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestViewSwitching(t *testing.T) {
	out, toItter := &syncBuffer{}, &syncBuffer{}
	v := newView(out, toItter)
	v.bell = true
	resizes := 0
	var rmu sync.Mutex
	v.resize = func() { rmu.Lock(); resizes++; rmu.Unlock() }
	typed := make(chan []byte)
	v.keys = func() (cancelreader.CancelReader, error) {
		return &fakeKeys{typed: typed, cancel: make(chan struct{})}, nil
	}
	opened := make(chan string)
	closeDMs := make(chan struct{})
	v.openDMs = func(target string) {
		opened <- target
		<-closeDMs
	}
	itterR, itterW := io.Pipe()
	go v.pumpItter(itterR)
	done := make(chan struct{})
	runErr := make(chan error, 1)
	go func() { runErr <- v.run(done, nil) }()

	// Typing goes to itter, itter's output to the screen.
	typed <- []byte("eet hello\r")
	eventually(t, "keys reach itter", func() bool { return toItter.String() == "eet hello\r" })
	io.WriteString(itterW, "(alice)itter> ")
	eventually(t, "itter output shown", func() bool { return strings.Contains(out.String(), "(alice)itter> ") })

	// The itter command dm: itter answers with a marker, the DMs open.
	io.WriteString(itterW, markerStart+"dm;@bob\a")
	if target := <-opened; target != "bob" {
		t.Fatalf("opened with %q", target)
	}
	if strings.Contains(out.String(), "7777") {
		t.Fatal("the marker reached the screen")
	}
	// While they are open, itter's output is kept back...
	io.WriteString(itterW, "new eet from carol")
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(out.String(), "carol") {
		t.Fatal("itter wrote over the DM view")
	}
	// ...and shown after.
	closeDMs <- struct{}{}
	eventually(t, "held output shown", func() bool { return strings.Contains(out.String(), "new eet from carol") })
	eventually(t, "itter told the size", func() bool { rmu.Lock(); defer rmu.Unlock(); return resizes > 0 })

	// Ctrl-] opens them too; what was typed before it still goes to itter.
	typed <- []byte("ab\x1dcd")
	if target := <-opened; target != "" {
		t.Fatalf("opened with %q", target)
	}
	eventually(t, "keys before Ctrl-]", func() bool { return strings.HasSuffix(toItter.String(), "ab") })
	closeDMs <- struct{}{}

	// New DMs: the title says so, and the bell rings once.
	before := len(out.String())
	v.setUnread(2)
	eventually(t, "title", func() bool {
		return strings.Contains(out.String()[before:], "\x1b]0;itter — 2 new DMs (type dm)\a\a")
	})
	// Not in the middle of an escape sequence from itter, though.
	io.WriteString(itterW, "\x1b[3")
	eventually(t, "partial sequence shown", func() bool { return strings.HasSuffix(out.String(), "\x1b[3") })
	v.setUnread(3)
	time.Sleep(30 * time.Millisecond)
	if !strings.HasSuffix(out.String(), "\x1b[3") {
		t.Fatal("the title went into the middle of itter's escape sequence")
	}
	io.WriteString(itterW, "1m")
	eventually(t, "title after the sequence", func() bool {
		return strings.HasSuffix(out.String(), "\x1b[31m\x1b]0;itter — 3 new DMs (type dm)\a\a")
	})

	close(done)
	if err := <-runErr; err != nil {
		t.Fatal(err)
	}
	itterW.Close()
}

// fakeItter is an SSH server that behaves like itter where it matters here:
// logins by key, sign-up as "register:<name>", a word of explanation (banner)
// when a name is taken, and a shell.
type fakeItter struct {
	mu   sync.Mutex
	keys map[string]string // user -> authorized key
	addr string
}

func startFakeItter(t *testing.T) *fakeItter {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	f := &fakeItter{keys: map[string]string{"taken": "x"}}
	cfg := &ssh.ServerConfig{
		BannerCallback: func(c ssh.ConnMetadata) string {
			if c.User() == "register:taken" {
				return "Sorry, the username 'taken' is already taken.\r\n"
			}
			return ""
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if name, ok := strings.CutPrefix(c.User(), "register:"); ok {
				if _, exists := f.keys[name]; exists {
					return nil, errors.New("taken")
				}
				return &ssh.Permissions{Extensions: map[string]string{"register": name, "key": string(key.Marshal())}}, nil
			}
			if f.keys[c.User()] == string(key.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("no")
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.addr = ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for r := range creqs {
							r.Reply(true, nil)
							if r.Type == "shell" {
								if name := sc.Permissions.Extensions["register"]; name != "" {
									f.mu.Lock()
									f.keys[name] = sc.Permissions.Extensions["key"]
									f.mu.Unlock()
									io.WriteString(ch, "Success! Account '"+name+"' created.\r\n")
									ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
									ch.Close()
								}
							}
						}
					}()
				}
			}()
		}
	}()
	return f
}

func TestLoginOrSignUp(t *testing.T) {
	f := startFakeItter(t)
	tun := &relay.Tunnel{Addr: f.addr, PinFile: filepath.Join(t.TempDir(), "itter_host_key")}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	keys := &accountKeys{ready: []ssh.Signer{signer}}
	answers := func(s string) *prompter { return &prompter{in: bufio.NewReader(strings.NewReader(s)), out: io.Discard} }

	// A name this device used before is not signed up again.
	if _, err := loginOrSignUp(tun, "carol", keys, answers("y\n"), false); err == nil {
		t.Fatal("logged in without an account")
	}
	// A new name: declining creates nothing...
	if _, err := loginOrSignUp(tun, "carol", keys, answers("n\n"), true); err == nil {
		t.Fatal("logged in after declining")
	}
	// ...accepting creates the account with the key, and logs in.
	cli, err := loginOrSignUp(tun, "carol", keys, answers("y\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	cli.Close()
	// From now on the key just works.
	if cli, err = tun.Login(context.Background(), "carol", clientVersion(), ssh.PublicKeys(signer)); err != nil {
		t.Fatal(err)
	}
	cli.Close()
	// A taken name: itter's explanation is passed on.
	_, err = loginOrSignUp(tun, "taken", keys, answers("y\n"), true)
	if err == nil || !strings.Contains(explainLocal(err), "already taken") {
		t.Fatalf("taken name: %v", err)
	}
}
