package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rrmn/itter-client/internal/relay"
)

// TestItterAppDM runs itter's own SSH server (the Python app, through its
// tests/dm_gate_server.py) and checks what the itter view relies on: itter
// recognises this program and answers `dm` with the marker the view catches,
// and tells plain ssh where to get the program instead.
//
// It runs where the app is: ITTER_APP=/path/to/itter, and ITTER_APP_PYTHON
// if its Python is not python3 on the PATH (the app's .venv/bin/python, say).
func TestItterAppDM(t *testing.T) {
	app := os.Getenv("ITTER_APP")
	if app == "" {
		t.Skip("ITTER_APP is not set")
	}
	python := os.Getenv("ITTER_APP_PYTHON")
	if python == "" {
		python = "python3"
	}
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	pubFile := filepath.Join(dir, "alice.pub")
	os.WriteFile(pubFile, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	cmd := exec.Command(python, "-m", "tests.dm_gate_server", "--port", port, "--relay", "127.0.0.1:9",
		"--user", "alice", "--user-key", pubFile)
	cmd.Dir = app
	cmd.Stderr = os.Stderr
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "DM entrance on") {
				ready <- true
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("itter's server did not start")
		}
	case <-time.After(60 * time.Second):
		t.Fatal("itter's server did not start in time")
	}

	tun := &relay.Tunnel{Addr: "127.0.0.1:" + port, PinFile: filepath.Join(dir, "itter_host_key")}
	// dm types `dm @bob` into an itter session made with the given client
	// version and returns what itter answers, up to the expected part.
	dm := func(clientVer, expect string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cli, err := tun.Login(ctx, "alice", clientVer, ssh.PublicKeys(signer))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer cli.Close()
		sess, err := cli.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		in, _ := sess.StdinPipe()
		from, _ := sess.StdoutPipe()
		if err := sess.RequestPty("xterm-256color", 40, 100, nil); err != nil {
			t.Fatal(err)
		}
		if err := sess.Shell(); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		chunks := make(chan []byte, 16)
		go func() {
			b := make([]byte, 4096)
			for {
				n, err := from.Read(b)
				if n > 0 {
					chunks <- bytes.Clone(b[:n])
				}
				if err != nil {
					close(chunks)
					return
				}
			}
		}()
		waitFor := func(s string) {
			deadline := time.After(20 * time.Second)
			for !strings.Contains(buf.String(), s) {
				select {
				case c, ok := <-chunks:
					if !ok {
						t.Fatalf("session ended before %q; got %q", s, buf.String())
					}
					buf.Write(c)
				case <-deadline:
					t.Fatalf("no %q in %q", s, buf.String())
				}
			}
		}
		waitFor("(alice)itter> ")
		buf.Reset()
		io.WriteString(in, "dm @bob\r")
		waitFor(expect)
		return buf.String()
	}

	got := dm(clientVersion(), markerStart+"dm;@bob\a")
	if !strings.Contains(got, markerStart+"dm;@bob\a") {
		t.Fatalf("the program got no DM marker: %q", got)
	}
	var s markerScanner
	var text bytes.Buffer
	var markers []string
	s.feed([]byte(got), func(p []byte) { text.Write(p) }, func(m string) { markers = append(markers, m) })
	s.flush(func(p []byte) { text.Write(p) })
	if target, ok := parseMarker(markers[0]); len(markers) != 1 || !ok || target != "bob" {
		t.Fatalf("markers %q", markers)
	}
	if strings.Contains(text.String(), "curl -fsSL") {
		t.Fatalf("the program was told to install itself: %q", text.String())
	}

	got = dm("SSH-2.0-OpenSSH_9.6", "Have fun!")
	if strings.Contains(got, "\x1b]7777") || !strings.Contains(got, "curl -fsSL") {
		t.Fatalf("plain ssh: %q", got)
	}
}
