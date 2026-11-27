package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rrmn/itter-client/internal/gatetest"
	"github.com/rrmn/itter-client/internal/relay"
	"github.com/rrmn/itter-client/internal/server"
	"github.com/rrmn/itter-client/internal/vault"
)

// gateWorld is how things are deployed: the relay listens for itter's SSH
// app only, and clients come in through the SSH port.
type gateWorld struct {
	*world
	gate *gatetest.Gate
}

func newGateWorld(t *testing.T) *gateWorld {
	mem := server.NewMemStore()
	ts := httptest.NewUnstartedServer(server.New(mem, server.Options{}).Handler())
	ts.Listener = server.ProxyListener(ts.Listener)
	ts.Start()
	t.Cleanup(ts.Close)
	gate, err := gatetest.Start("127.0.0.1:0", ts.Listener.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	isolateHome(t)
	t.Setenv("ITTER_RELAY", "")
	t.Setenv("ITTER_HOST", gate.Addr)
	return &gateWorld{world: &world{mem: mem, ts: ts}, gate: gate}
}

func TestThroughTheSSHPort(t *testing.T) {
	w := newGateWorld(t)
	alice, bob := w.ready(t, "alice"), w.ready(t, "bob")
	top := t // a gate started inside a subtest has to outlive it

	t.Run("setup, send and receive need nothing but itter's address", func(t *testing.T) {
		alice.mustSend("bob", "through port 22")
		expectTexts(t, bob.pull("alice"), "through port 22")
		bob.mustSend("alice", "and back")
		expectTexts(t, alice.pull("bob"), "and back")
		alice.use()
		out, err := capture(cmdStatus)
		if err != nil || !strings.Contains(out, "itter (ssh "+w.gate.Addr+") — connected") {
			t.Fatalf("status: %q, %v", out, err)
		}
		if n := w.gate.Channels.Load(); n == 0 {
			t.Fatal("nothing went through the gate")
		}
	})

	t.Run("a plain HTTP client cannot talk to the relay", func(t *testing.T) {
		resp, err := http.Get(w.ts.URL + "/v1/keys/alice")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("the relay answered a client that did not come through the gate: %s", resp.Status)
		}
	})

	t.Run("the server's host key is remembered, and a different one stops everything", func(t *testing.T) {
		pin := filepath.Join(alice.dir, hostKeyFile)
		if b, err := os.ReadFile(pin); err != nil || !strings.HasPrefix(string(b), w.gate.Addr+" ") {
			t.Fatalf("no host key on record: %q, %v", b, err)
		}
		addr, relayAddr, key := w.gate.Addr, w.gate.Relay, w.gate.Signer
		w.gate.Close()
		impostor, err := gatetest.Start(addr, relayAddr, nil)
		if err != nil {
			t.Skipf("could not listen on %s again: %v", addr, err)
		}
		out := alice.send("bob", "who is listening?")
		if out.Status != vault.StatusQueued || !strings.Contains(out.Note, "different SSH host key") || !strings.Contains(out.Note, "itter_host_key") {
			t.Fatalf("sent to a server with another host key: %+v", out)
		}
		if impostor.Logins.Load() != 0 {
			t.Fatal("the client logged in to a server it should not trust")
		}
		impostor.Close()
		// The real server is back: what was queued goes out.
		w.gate, err = gatetest.Start(addr, relayAddr, key)
		if err != nil {
			t.Skipf("could not listen on %s again: %v", addr, err)
		}
		top.Cleanup(w.gate.Close)
		if err := alice.app().flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		expectTexts(t, bob.pull("alice"), "who is listening?")
	})

	t.Run("an open shell survives the server going away", func(t *testing.T) {
		logins := w.gate.Logins.Load()
		a := alice.app() // one process, one SSH connection for everything it does
		if out, err := a.send("bob", "before"); err != nil || out.Status != vault.StatusSent {
			t.Fatalf("send: %+v, %v", out, err)
		}
		if _, err := a.pull(0); err != nil {
			t.Fatal(err)
		}
		if n := w.gate.Logins.Load() - logins; n != 1 {
			t.Fatalf("%d SSH connections for one process, want 1", n)
		}
		addr, relayAddr, key := w.gate.Addr, w.gate.Relay, w.gate.Signer
		w.gate.Close()
		out, err := a.send("bob", "during")
		if err != nil || out.Status != vault.StatusQueued {
			t.Fatalf("send without a server: %+v, %v", out, err)
		}
		g, err := gatetest.Start(addr, relayAddr, key)
		if err != nil {
			t.Skipf("could not listen on %s again: %v", addr, err)
		}
		w.gate = g
		top.Cleanup(g.Close)
		if err := a.flush(); err != nil {
			t.Fatalf("flush after the server came back: %v", err)
		}
		expectTexts(t, bob.pull("alice"), "before", "during")
	})

	t.Run("a server without the entrance says so", func(t *testing.T) {
		w.gate.Lock()
		w.gate.Closed = true
		w.gate.Unlock()
		defer func() {
			w.gate.Lock()
			w.gate.Closed = false
			w.gate.Unlock()
		}()
		out := alice.send("bob", "anyone?")
		if out.Status != vault.StatusQueued || !strings.Contains(out.Note, "no entrance for DMs") {
			t.Fatalf("got %+v", out)
		}
	})
}

func TestItterHost(t *testing.T) {
	for in, want := range map[string]string{
		"":                    defaultHost,
		"itter.example":       "itter.example:22",
		"itter.example:8022":  "itter.example:8022",
		"127.0.0.1":           "127.0.0.1:22",
		"::1":                 "[::1]:22",
		"[::1]":               "[::1]:22",
		"[::1]:8022":          "[::1]:8022",
		" localhost:8022 ":    "localhost:8022",
		"itter.example:0":     "",
		"itter.example:port":  "",
		"itter.example:99999": "",
		":22":                 "",
	} {
		t.Setenv("ITTER_HOST", in)
		got, err := itterHost()
		if (err != nil) != (want == "") || got != want {
			t.Errorf("ITTER_HOST=%q: %q, %v; want %q", in, got, err, want)
		}
	}
	// ITTER_RELAY, when set, wins: a relay on this machine needs no SSH.
	t.Setenv("ITTER_HOST", "itter.example")
	t.Setenv("ITTER_RELAY", "http://127.0.0.1:8080")
	if rc, err := newRelay(); err != nil || rc.Where() != "http://127.0.0.1:8080" {
		t.Fatalf("newRelay with ITTER_RELAY: %v, %v", rc, err)
	}
	t.Setenv("ITTER_RELAY", "")
	t.Setenv("ITTER_DIR", t.TempDir())
	if rc, err := newRelay(); err != nil || rc.Where() != "itter (ssh itter.example:22)" {
		t.Fatalf("newRelay: %v, %v", rc, err)
	}
}

// --- the SSH key of the account, without ssh-agent ---

// keyFile writes an SSH private key into the (test's own) ~/.ssh.
func keyFile(t *testing.T, name string, key any, passphrase string) string {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase != "" {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "test", []byte(passphrase))
	} else {
		block, err = ssh.MarshalPrivateKey(key, "test")
	}
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	path := name
	if !filepath.IsAbs(name) {
		path = filepath.Join(home, ".ssh", name)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// account creates an itter account for a fresh Ed25519 key and returns a
// user without an agent, and the key.
func (w *world) account(t *testing.T, name string) (*user, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	w.mem.AddUser(name, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))))
	return &user{t: t, name: name, dir: filepath.Join(t.TempDir(), "state")}, priv
}

// shortDir is a temporary directory with a short path: a Unix socket's path
// may not be longer than about a hundred characters, and t.TempDir() of a
// subtest with a long name is.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "itter-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// asked replaces the passphrase prompt and counts how often it is used.
func asked(t *testing.T, answers ...string) *int {
	n := 0
	old := readPassphrase
	readPassphrase = func(prompt string) ([]byte, error) {
		n++
		if len(answers) == 0 {
			t.Errorf("unexpected passphrase prompt: %q", prompt)
			return nil, userErrf("no answer")
		}
		a := answers[0]
		if len(answers) > 1 {
			answers = answers[1:]
		}
		return []byte(a), nil
	}
	t.Cleanup(func() { readPassphrase = old })
	return &n
}

func TestSetupFindsTheKeyByItself(t *testing.T) {
	w := newWorld(t)

	t.Run("a key file in ~/.ssh, no agent", func(t *testing.T) {
		isolateHome(t)
		alice, key := w.account(t, "alice")
		keyFile(t, "id_ed25519", key, "")
		prompts := asked(t)
		if out, err := alice.setup(); err != nil || !strings.Contains(out, "This device is @alice") {
			t.Fatalf("setup: %q, %v", out, err)
		}
		if *prompts != 0 {
			t.Fatal("asked for a passphrase the key does not have")
		}
	})

	t.Run("a key file with a passphrase: asked once, and only when needed", func(t *testing.T) {
		isolateHome(t)
		bob, key := w.account(t, "bob")
		path := keyFile(t, "id_ed25519", key, "correct horse")
		prompts := asked(t, "wrong", "correct horse")
		if out, err := bob.setup(); err != nil || !strings.Contains(out, "This device is @bob") {
			t.Fatalf("setup: %q, %v", out, err)
		}
		if *prompts != 2 {
			t.Fatalf("%d passphrase prompts, want 2 (one wrong, one right)", *prompts)
		}
		_ = path
	})

	t.Run("the agent is tried first; the file only if the agent's keys are not the account's", func(t *testing.T) {
		isolateHome(t)
		carol, key := w.account(t, "carol")
		keyFile(t, "id_ed25519", key, "s3cret")
		_, other, _ := ed25519.GenerateKey(rand.Reader)
		carol.sock = startAgent(t, shortDir(t), other) // a key itter has never seen
		prompts := asked(t, "s3cret")
		if _, err := carol.setup(); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if *prompts != 1 {
			t.Fatalf("%d passphrase prompts, want 1", *prompts)
		}

		// With the right key in the agent, the file is left alone.
		isolateHome(t)
		dave, dkey := w.account(t, "dave")
		_, unrelated, _ := ed25519.GenerateKey(rand.Reader)
		keyFile(t, "id_ed25519", unrelated, "never asked for")
		dave.sock = startAgent(t, shortDir(t), dkey)
		prompts = asked(t)
		if _, err := dave.setup(); err != nil {
			t.Fatalf("setup: %v", err)
		}
	})

	t.Run("three wrong passphrases: nothing is lost", func(t *testing.T) {
		isolateHome(t)
		erin, key := w.account(t, "erin")
		keyFile(t, "id_ed25519", key, "right")
		prompts := asked(t, "wrong")
		_, err := erin.setup()
		if err == nil || !strings.Contains(err.Error(), "not the passphrase of ~/.ssh/id_ed25519") || !strings.Contains(err.Error(), "identity is kept") {
			t.Fatalf("got %v", err)
		}
		if *prompts != 3 {
			t.Fatalf("%d prompts, want 3", *prompts)
		}
		asked(t, "right")
		if out, err := erin.setup(); err != nil || !strings.Contains(out, "Resuming setup") {
			t.Fatalf("second try: %q, %v", out, err)
		}
	})

	t.Run("ITTER_KEY names a key that is somewhere else", func(t *testing.T) {
		isolateHome(t)
		frank, key := w.account(t, "frank")
		_, decoy, _ := ed25519.GenerateKey(rand.Reader)
		keyFile(t, "id_ed25519", decoy, "must not be asked for") // not looked at when ITTER_KEY is set
		asked(t)
		t.Setenv("ITTER_KEY", keyFile(t, filepath.Join(t.TempDir(), "itter_key"), key, ""))
		if _, err := frank.setup(); err != nil {
			t.Fatalf("setup: %v", err)
		}
		gina, _ := w.account(t, "gina")
		t.Setenv("ITTER_KEY", filepath.Join(t.TempDir(), "nope"))
		if _, err := gina.setup(); err == nil || !strings.Contains(err.Error(), "ITTER_KEY") {
			t.Fatalf("missing ITTER_KEY file: %v", err)
		}
	})

	t.Run("no key, the wrong key, only RSA: each says what to do", func(t *testing.T) {
		isolateHome(t)
		hank, _ := w.account(t, "hank")
		_, err := hank.setup()
		if err == nil || !strings.Contains(err.Error(), "no SSH key found") || !strings.Contains(err.Error(), "ssh-agent, ~/.ssh/id_ed25519, ~/.ssh/id_ecdsa") {
			t.Fatalf("no key at all: %v", err)
		}
		if vault.Exists(hank.dir) {
			t.Fatal("a vault was created although setup could not start")
		}

		_, stranger, _ := ed25519.GenerateKey(rand.Reader)
		keyFile(t, "id_ed25519", stranger, "")
		_, err = hank.setup()
		if err == nil || !strings.Contains(err.Error(), "none of your SSH keys belongs to @hank") {
			t.Fatalf("a key itter does not know: %v", err)
		}
		if vault.Exists(hank.dir) {
			t.Fatal("the identity of a refused registration was kept")
		}

		isolateHome(t)
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		keyFile(t, "id_ed25519", rsaKey, "") // whatever the file is called
		_, err = hank.setup()
		if err == nil || !strings.Contains(err.Error(), "only RSA keys were found") {
			t.Fatalf("RSA only: %v", err)
		}
	})
}

// --- the first run ---

func TestFirstRun(t *testing.T) {
	w := newWorld(t)
	asked(t)
	run := func(u *user, typed string) (string, error) {
		u.use()
		return capture(func() error { return firstRun(strings.NewReader(typed), os.Stdout) })
	}

	t.Run("it asks who you are and sets the device up", func(t *testing.T) {
		alice, key := w.account(t, "alice")
		keyFile(t, "id_ed25519", key, "")
		alice.use()
		if !needsFirstRun() {
			t.Fatal("a device without a vault does not need a first run?")
		}
		out, err := run(alice, "@alice\n\n")
		if err != nil {
			t.Fatalf("first run: %v\n%s", err, out)
		}
		for _, want := range []string{"Your itter username", "RECOVERY CODE", "Done. This device is @alice", "compare safety numbers", "Press Enter to open the chat"} {
			if !strings.Contains(out, want) {
				t.Errorf("first run does not show %q:\n%s", want, out)
			}
		}
		alice.use()
		if needsFirstRun() {
			t.Fatal("still not set up")
		}
		if _, err := alice.app().send("alice2", "x"); err == nil {
			t.Fatal("sent to a user that does not exist")
		}
	})

	t.Run("the computer's user name is offered, Enter takes it", func(t *testing.T) {
		bob, key := w.account(t, "bob")
		isolateHome(t)
		keyFile(t, "id_ed25519", key, "")
		t.Setenv("ITTER_USER", "")
		t.Setenv("LOGNAME", "someone_else")
		t.Setenv("USER", "bob")
		out, err := run(bob, "\n\n")
		if err != nil || !strings.Contains(out, "Your itter username [bob]:") || !strings.Contains(out, "This device is @bob") {
			t.Fatalf("first run: %v\n%s", err, out)
		}
		t.Setenv("USER", "not a valid name!")
		if got := guessUsername(); got != "someone_else" {
			t.Fatalf("guess = %q, want the next name that could be one", got)
		}
		t.Setenv("LOGNAME", "x")
		if got := guessUsername(); got != "" {
			t.Fatalf("offered %q, a name itter would not accept", got)
		}
	})

	t.Run("nonsense for a username sets nothing up", func(t *testing.T) {
		isolateHome(t)
		nobody := &user{t: t, name: "x", dir: filepath.Join(t.TempDir(), "state")}
		check := func(typed, want string) {
			t.Helper()
			out, err := run(nobody, typed)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("typed %q: %v\n%s", typed, err, out)
			}
			if vault.Exists(nobody.dir) || strings.Contains(out, "RECOVERY CODE") {
				t.Fatalf("typed %q: something was set up\n%s", typed, out)
			}
		}
		check("x y\n", "not a valid itter username")
		check("", "no answer")
		check("ghost\n", "no SSH key found")
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keyFile(t, "id_ed25519", key, "")
		check("ghost\n", "there is no itter user @ghost")
	})

	t.Run("an account that already uses DMs: this device is added to it", func(t *testing.T) {
		isolateHome(t)
		carol, key := w.account(t, "carol")
		keyFile(t, "id_ed25519", key, "")
		if _, err := carol.setup(); err != nil {
			t.Fatal(err)
		}
		laptop := carol.second(t)

		// "n": nothing happens. And nothing was made up front: a recovery code
		// shown here would belong to an identity that never comes to be.
		out, err := run(laptop, "carol\nn\n")
		if err == nil || !strings.Contains(out, "@carol already uses DMs on another device") || vault.Exists(laptop.dir) {
			t.Fatalf("declined: %v, exists=%v\n%s", err, vault.Exists(laptop.dir), out)
		}
		if strings.Contains(out, "RECOVERY CODE") || strings.Contains(out, "Generating identity") {
			t.Fatalf("an identity was generated for an account that has one:\n%s", out)
		}

		// Enter: it shows a code, and the first device lets it in.
		old := linkPoll
		linkPoll = 300 * time.Millisecond
		defer func() { linkPoll = old }()
		done := make(chan error, 1)
		go func() {
			_, err := run(laptop, "carol\n\n\n")
			done <- err
		}()
		var secret []byte
		deadline := time.Now().Add(30 * time.Second)
		for len(secret) == 0 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
			if v, err := vault.Open(laptop.dir); err == nil {
				secret = v.LinkSecret
			}
		}
		if len(secret) == 0 {
			t.Fatal("the new device never showed a link code")
		}
		first := &app{rc: relay.New(w.ts.URL)}
		if first.v, err = vault.Open(carol.dir); err != nil {
			t.Fatal(err)
		}
		for {
			_, err := first.approve(secret)
			if err == nil {
				break
			}
			if !strings.Contains(err.Error(), "no device is waiting") || time.Now().After(deadline) {
				t.Fatalf("approve: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("first run with linking: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the first run did not finish")
		}
		if v, err := vault.Open(laptop.dir); err != nil || !v.IsLinked() {
			t.Fatalf("the device was not linked: %v", err)
		}
	})

	t.Run("a setup that was interrupted is finished without questions", func(t *testing.T) {
		isolateHome(t)
		dora, key := w.account(t, "dora")
		keyFile(t, "id_ed25519", key, "")
		dora.use()
		withNetwork(&flaky{match: func(r *http.Request) bool { return r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/v1/keys/") }}, func() {
			if _, err := capture(func() error { return cmdSetup([]string{"dora"}) }); err == nil {
				t.Fatal("setup succeeded without publishing prekeys")
			}
		})
		dora.use()
		if !needsFirstRun() {
			t.Fatal("a half-finished setup is not noticed")
		}
		out, err := run(dora, "")
		if err != nil || !strings.Contains(out, "Finishing the setup for @dora") || strings.Contains(out, "Your itter username") {
			t.Fatalf("resume: %v\n%s", err, out)
		}
		dora.use()
		if needsFirstRun() {
			t.Fatal("still not finished")
		}
	})

	t.Run("without a terminal nothing is asked", func(t *testing.T) {
		isolateHome(t)
		t.Setenv("ITTER_DIR", filepath.Join(t.TempDir(), "state"))
		old := interactive
		interactive = func() bool { return false }
		defer func() { interactive = old }()
		err := cmdShell()
		if err == nil || !strings.Contains(err.Error(), "not set up for DMs yet") || !strings.Contains(err.Error(), "run `itter`") {
			t.Fatalf("got %v", err)
		}
	})
}
