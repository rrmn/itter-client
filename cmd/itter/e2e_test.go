package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/rrmn/itter-client/internal/api"
	"github.com/rrmn/itter-client/internal/pqc"
	"github.com/rrmn/itter-client/internal/relay"
	"github.com/rrmn/itter-client/internal/server"
	"github.com/rrmn/itter-client/internal/vault"
)

// End-to-end tests: the real CLI code paths for several users talking through
// an in-memory relay, with an in-process ssh-agent and a mocked OS keychain.

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

type world struct {
	mem *server.MemStore
	ts  *httptest.Server

	mu    sync.Mutex
	relay http.Handler // the relay behind ts; restart() puts a new one there
	// tap, if set, is shown every request (with its body) before the relay
	// gets it: what someone who can read the connection sees.
	tap func(r *http.Request, body []byte)
}

func newWorld(t *testing.T) *world {
	w := &world{mem: server.NewMemStore()}
	w.restart()
	w.ts = httptest.NewServer(http.HandlerFunc(w.serve))
	t.Cleanup(w.ts.Close)
	t.Setenv("ITTER_RELAY", w.ts.URL)
	isolateHome(t)
	return w
}

// restart replaces the relay by a new process' worth of it: the same store,
// but nothing that was only in memory (it has no ITTER_TOKEN_KEY).
func (w *world) restart() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.relay = server.New(w.mem, server.Options{}).Handler()
}

func (w *world) serve(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	h, tap := w.relay, w.tap
	w.mu.Unlock()
	if tap != nil {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		tap(r, body)
	}
	h.ServeHTTP(rw, r)
}

// isolateHome gives the test a home directory of its own, so that the keys
// in the real ~/.ssh of whoever runs the tests are never looked at.
func isolateHome(t *testing.T) string {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("ITTER_KEY", "")
	t.Setenv("ITTER_HOST", "")
	return home
}

type user struct {
	t    *testing.T
	name string
	dir  string
	sock string
}

func startAgent(t *testing.T, dir string, keys ...any) string {
	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(kr, c)
		}
	}()
	return sock
}

// newUser creates an itter account (on the "itter server") with one SSH key
// in an agent. It does not set up DMs.
func (w *world) newUser(t *testing.T, name string, rsaOnly bool) *user {
	dir, err := os.MkdirTemp("", "itter-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	var priv any
	var pub ssh.PublicKey
	if rsaOnly {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		priv = k
		pub, _ = ssh.NewPublicKey(&k.PublicKey)
	} else {
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		priv = sk
		pub, _ = ssh.NewPublicKey(pk)
	}
	w.mem.AddUser(name, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))))
	return &user{t: t, name: name, dir: filepath.Join(dir, "state"), sock: startAgent(t, dir, priv)}
}

// ready creates a user and sets up DMs.
func (w *world) ready(t *testing.T, name string) *user {
	t.Helper()
	u := w.newUser(t, name, false)
	if _, err := u.setup(); err != nil {
		t.Fatalf("setup %s: %v", name, err)
	}
	return u
}

func (u *user) use() {
	u.t.Setenv("ITTER_DIR", u.dir)
	u.t.Setenv("SSH_AUTH_SOCK", u.sock)
}

// capture runs fn and returns what it printed.
func capture(fn func() error) (string, error) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	err := fn()
	w.Close()
	os.Stdout = old
	return <-done, err
}

func (u *user) setup() (string, error) {
	u.use()
	return capture(func() error { return cmdSetup([]string{u.name}) })
}

// app opens the vault the way a fresh `itter` process would.
func (u *user) app() *app {
	u.t.Helper()
	u.use()
	a, err := open()
	if err != nil {
		u.t.Fatalf("open %s: %v", u.name, err)
	}
	return a
}

func (u *user) send(to, text string) sendOutcome {
	u.t.Helper()
	out, err := u.app().send(to, text)
	if err != nil {
		u.t.Fatalf("%s -> %s: %v", u.name, to, err)
	}
	return out
}

// mustSend sends and insists the relay took it.
func (u *user) mustSend(to, text string) {
	u.t.Helper()
	if out := u.send(to, text); out.Status != vault.StatusSent {
		u.t.Fatalf("%s -> %s: status %d (%s), want sent", u.name, to, out.Status, out.Note)
	}
}

// pull fetches everything and returns the lines that were added to the
// conversation with peer ("SYSTEM: …" for notices).
func (u *user) pull(peer string) []string {
	u.t.Helper()
	a := u.app()
	before := len(a.v.GetMessages(peer))
	if _, err := a.pull(0); err != nil {
		u.t.Fatalf("%s pull: %v", u.name, err)
	}
	return render(a.v.GetMessages(peer)[before:])
}

// firstBundle returns the keys of name's first device as the public
// directory lists them (no one-time prekey).
func firstBundle(t testing.TB, rc *relay.Client, name string) *pqc.PublicBundle {
	t.Helper()
	d, err := rc.Directory(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range d.Devices {
		if pqc.IdentityEqual(b.Identity, d.Identity) {
			return b
		}
	}
	t.Fatalf("%s has no first device in the directory", name)
	return nil
}

// rawWire marshals a message the way a's device would send it.
func rawWire(a *app, w *pqc.WireMsg) []byte {
	w.Dev = a.v.DeviceID()
	raw, _ := json.Marshal(w)
	return raw
}

// post sends one raw message to the first device of an account (whose device
// ID is the ID of the account identity).
func post(a *app, to string, raw []byte, toID string) error {
	return a.rc.Send(a.auth(), to, toID, map[string][]byte{toID: raw})
}

// queue encrypts payload for every device of to and puts it into a's outbox,
// without any of the checks send makes. It runs inside v.Update.
func queue(a *app, to, id string, payload []byte) error {
	q, err := a.sealAll(to, id, payload)
	if err != nil {
		return err
	}
	a.v.QueueBatch(*q)
	return nil
}

func render(msgs []vault.ChatMsg) []string {
	var out []string
	for _, m := range msgs {
		switch {
		case m.IsSystem:
			out = append(out, "SYSTEM: "+m.Text)
		case !m.IsOut:
			out = append(out, m.Text)
		}
	}
	return out
}

func texts(lines []string) []string {
	out := []string{}
	for _, l := range lines {
		if !strings.HasPrefix(l, "SYSTEM: ") {
			out = append(out, l)
		}
	}
	return out
}

func notices(lines []string) string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, "SYSTEM: ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func expectTexts(t *testing.T, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(texts(got)) != fmt.Sprint(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func (u *user) burn(extra ...string) (string, error) {
	u.use()
	r, w, _ := os.Pipe()
	fmt.Fprintln(w, "BURN")
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	return capture(func() error { return cmdBurn(extra) })
}

// flaky is a network that misbehaves for selected requests.
type flaky struct {
	match func(*http.Request) bool
	after bool // let the request through, then lose the response
	hits  int
}

func (f *flaky) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.match != nil && f.match(r) {
		f.hits++
		if f.after {
			if resp, err := http.DefaultTransport.RoundTrip(r); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		return nil, errors.New("simulated network failure")
	}
	return http.DefaultTransport.RoundTrip(r)
}

func withNetwork(f *flaky, fn func()) {
	relay.Transport = f
	defer func() { relay.Transport = nil }()
	fn()
}

func isSend(r *http.Request) bool {
	return r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/msg/")
}

// --- the tests ---

func TestSetup(t *testing.T) {
	w := newWorld(t)

	t.Run("an agent with only RSA keys is refused", func(t *testing.T) {
		carol := w.newUser(t, "carol", true)
		_, err := carol.setup()
		if err == nil || !strings.Contains(err.Error(), "RSA") {
			t.Fatalf("expected an RSA refusal, got %v", err)
		}
		if vault.Exists(carol.dir) {
			t.Fatal("a vault was created although setup could not start")
		}
	})

	t.Run("setup shows the recovery code and is idempotent", func(t *testing.T) {
		alice := w.newUser(t, "alice", false)
		out, err := alice.setup()
		if err != nil {
			t.Fatal(err)
		}
		a := alice.app()
		code, _ := a.v.RecoveryCode()
		if !strings.Contains(out, api.FormatRecovery(code)) {
			t.Fatalf("setup did not print the recovery code:\n%s", out)
		}
		out, err = alice.setup()
		if err != nil || !strings.Contains(out, "Already set up") {
			t.Fatalf("second setup: %q, %v", out, err)
		}
	})

	t.Run("a lost registration response does not lock the account", func(t *testing.T) {
		bob := w.newUser(t, "bob", false)
		f := &flaky{after: true, match: func(r *http.Request) bool { return r.Method == "PUT" && r.URL.Path == "/v1/register" }}
		withNetwork(f, func() {
			_, err := bob.setup()
			if err == nil || !strings.Contains(err.Error(), "again") {
				t.Fatalf("expected a 'run setup again' error, got %v", err)
			}
		})
		if f.hits != 1 || !vault.Exists(bob.dir) {
			t.Fatal("the identity must be kept when the outcome of registration is unknown")
		}
		bob.use()
		if _, err := open(); err == nil || !strings.Contains(err.Error(), "did not finish") {
			t.Fatalf("an unfinished setup must not be usable: %v", err)
		}
		out, err := bob.setup() // the relay already has this identity: must simply complete
		if err != nil || !strings.Contains(out, "Resuming") {
			t.Fatalf("resume failed: %q, %v", out, err)
		}
		bob.app()
	})

	t.Run("a failed prekey upload can be resumed", func(t *testing.T) {
		dave := w.newUser(t, "dave", false)
		f := &flaky{match: func(r *http.Request) bool { return r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/v1/keys/") }}
		withNetwork(f, func() {
			if _, err := dave.setup(); err == nil {
				t.Fatal("expected an error")
			}
		})
		if _, err := dave.setup(); err != nil {
			t.Fatal(err)
		}
		alice := w.ready(t, "erin")
		alice.mustSend("dave", "works?")
		expectTexts(t, dave.pull("erin"), "works?")
	})

	t.Run("a second device cannot take the account; the recovery code frees it", func(t *testing.T) {
		frank := w.ready(t, "frank")
		code, _ := frank.app().v.RecoveryCode()
		lost := *frank // the old device, now out of reach
		newDev := &user{t: t, name: "frank", dir: filepath.Join(t.TempDir(), "state"), sock: frank.sock}
		_, err := newDev.setup()
		if err == nil || !strings.Contains(err.Error(), "itter recover") {
			t.Fatalf("expected a refusal that mentions recovery, got %v", err)
		}
		if vault.Exists(newDev.dir) {
			t.Fatal("the refused identity should not be left behind")
		}

		recoverWith := func(code string) error {
			newDev.use()
			r, wr, _ := os.Pipe()
			fmt.Fprintln(wr, code)
			wr.Close()
			old := os.Stdin
			os.Stdin = r
			defer func() { os.Stdin = old }()
			_, err := capture(func() error { return cmdRecover([]string{"frank"}) })
			return err
		}
		if err := recoverWith(api.FormatRecovery(bytes.Repeat([]byte{1}, 32))); err == nil {
			t.Fatal("a wrong recovery code was accepted")
		}
		if err := recoverWith(strings.ToLower(api.FormatRecovery(code))); err != nil {
			t.Fatalf("recovery failed: %v", err)
		}
		if _, err := newDev.setup(); err != nil {
			t.Fatalf("setup after recovery: %v", err)
		}
		// The lost device is locked out and says why.
		_, err = lost.app().pull(0)
		if err == nil || !strings.Contains(explain(err), "no longer knows this device") || !strings.Contains(explain(err), "`itter burn`, then run `itter`") {
			t.Fatalf("old device: %v", err)
		}
		// Following that advice works without --force: the relay refuses the
		// old identity's release, but there is nothing of it left to release.
		out, err := lost.burn()
		if err != nil || !strings.Contains(out, "different DM identity by now") || vault.Exists(lost.dir) {
			t.Fatalf("burn on the replaced device: %q, %v", out, err)
		}
		// The account's new identity is untouched by that.
		if _, err := newDev.app().rc.KeyCount(newDev.app().auth()); err != nil {
			t.Fatalf("the new device after the old one burned: %v", err)
		}
	})

	t.Run("burn refuses to strand the account when the relay is unreachable", func(t *testing.T) {
		gina := w.ready(t, "gina")
		f := &flaky{match: func(r *http.Request) bool { return r.Method == "DELETE" }}
		withNetwork(f, func() {
			if _, err := gina.burn(); err == nil || !strings.Contains(err.Error(), "Nothing was deleted") {
				t.Fatalf("got %v", err)
			}
		})
		if !vault.Exists(gina.dir) {
			t.Fatal("the vault was deleted although the release failed")
		}
		if _, err := gina.burn(); err != nil {
			t.Fatal(err)
		}
		if vault.Exists(gina.dir) {
			t.Fatal("vault still there")
		}
		if _, err := gina.setup(); err != nil { // released cleanly: a new setup just works
			t.Fatal(err)
		}
	})

	t.Run("names are matched the way itter does: ignoring case", func(t *testing.T) {
		hal := w.newUser(t, "Hal_9000", false)
		hal.name = "hal_9000" // typed in lower case
		if _, err := hal.setup(); err != nil {
			t.Fatal(err)
		}
		if me, _ := hal.app().v.Me(); me != "Hal_9000" {
			t.Fatalf("the vault should use itter's spelling, got %q", me)
		}
		ivy := w.ready(t, "ivy")
		if out := ivy.send("HAL_9000", "open the pod bay doors"); out.Target != "Hal_9000" {
			t.Fatalf("target %q", out.Target)
		}
		expectTexts(t, hal.pull("ivy"), "open the pod bay doors")
		hal.mustSend("IVY", "I'm sorry, Ivy")
		expectTexts(t, ivy.pull("Hal_9000"), "I'm sorry, Ivy")
		if n := len(ivy.app().v.ContactList()); n != 1 {
			t.Fatalf("%d contacts, want 1 (one person, one spelling)", n)
		}
	})
}

func TestConversation(t *testing.T) {
	w := newWorld(t)
	alice, bob := w.ready(t, "alice"), w.ready(t, "bob")

	t.Run("messages flow and both post-quantum ratchets advance", func(t *testing.T) {
		alice.mustSend("bob", "hi bob")
		alice.mustSend("bob", "are you there?")
		got := bob.pull("alice")
		expectTexts(t, got, "hi bob", "are you there?")
		if !strings.Contains(notices(got), "New conversation") {
			t.Fatalf("no first-contact notice: %q", got)
		}
		for i := 0; i < 30; i++ {
			bob.mustSend("alice", fmt.Sprintf("b%d", i))
			expectTexts(t, alice.pull("bob"), fmt.Sprintf("b%d", i))
			alice.mustSend("bob", fmt.Sprintf("a%d", i))
			expectTexts(t, bob.pull("alice"), fmt.Sprintf("a%d", i))
		}
		info, _ := alice.app().v.ContactInfo("bob")
		t.Logf("after 62 DMs through the relay: ML-KEM steps %d, FrodoKEM steps %d", info.MLKEM, info.Frodo)
		if info.MLKEM < 2 || info.Frodo < 2 || info.Stalled != "" {
			t.Fatalf("post-quantum ratchets did not advance: %+v", info)
		}
		if w.mem.Pending("alice")+w.mem.Pending("bob") != 0 {
			t.Fatal("acknowledged messages are still on the relay")
		}
	})

	t.Run("state is on disk before a message leaves; two processes never reuse a key", func(t *testing.T) {
		shell := alice.app()   // the open shell
		oneShot := alice.app() // `itter dm` in another terminal
		if _, err := oneShot.send("bob", "from the second terminal"); err != nil {
			t.Fatal(err)
		}
		if _, err := shell.send("bob", "from the shell"); err != nil {
			t.Fatal(err)
		}
		if _, err := oneShot.send("bob", "and again"); err != nil {
			t.Fatal(err)
		}
		expectTexts(t, bob.pull("alice"), "from the second terminal", "from the shell", "and again")
	})

	t.Run("offline: messages queue in order and go out later, exactly once", func(t *testing.T) {
		down := &flaky{match: isSend}
		withNetwork(down, func() {
			for i := 0; i < 3; i++ {
				out := alice.send("bob", fmt.Sprintf("queued %d", i))
				if out.Status != vault.StatusQueued || out.Note == "" {
					t.Fatalf("message %d: status %d note %q, want queued with a reason", i, out.Status, out.Note)
				}
			}
		})
		if got := bob.pull("alice"); len(got) != 0 {
			t.Fatalf("bob got %q while alice was offline", got)
		}
		// A crash here loses nothing: a new process finds the queue.
		a := alice.app()
		if n := len(a.v.OutboxSnapshot()); n != 3 {
			t.Fatalf("%d queued, want 3", n)
		}
		// The response to the first delivery is lost: it must not be delivered twice.
		lost := &flaky{after: true, match: func(r *http.Request) bool { return isSend(r) }}
		withNetwork(lost, func() {
			lost.match = func(r *http.Request) bool { ok := isSend(r) && lost.hits == 0; return ok }
			_ = alice.app().flush()
		})
		alice.mustSend("bob", "back online")
		expectTexts(t, bob.pull("alice"), "queued 0", "queued 1", "queued 2", "back online")
		for _, m := range alice.app().v.GetMessages("bob") {
			if m.IsOut && m.Status != vault.StatusSent {
				t.Fatalf("message %q still has status %d", m.Text, m.Status)
			}
		}
	})

	t.Run("a lost fetch or a lost ack loses nothing and shows nothing twice", func(t *testing.T) {
		alice.mustSend("bob", "one")
		alice.mustSend("bob", "two")
		// The response to the fetch is lost.
		lostFetch := &flaky{after: true, match: func(r *http.Request) bool { return strings.Contains(r.URL.Path, "/from/") }}
		withNetwork(lostFetch, func() {
			if _, err := bob.app().pull(0); err == nil {
				t.Fatal("expected the pull to fail")
			}
		})
		// The ack is lost after the messages were saved.
		lostAck := &flaky{match: func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/ack") }}
		var got []string
		withNetwork(lostAck, func() {
			a := bob.app()
			before := len(a.v.GetMessages("alice"))
			_, _ = a.pull(0)
			got = render(a.v.GetMessages("alice")[before:])
		})
		expectTexts(t, got, "one", "two")
		if w.mem.Pending("bob") != 2 {
			t.Fatal("the relay deleted messages without an ack")
		}
		if again := bob.pull("alice"); len(again) != 0 {
			t.Fatalf("redelivered messages were shown again: %q", again)
		}
		if w.mem.Pending("bob") != 0 {
			t.Fatal("redelivered messages were not acknowledged")
		}
	})

	t.Run("both sides writing first still converge", func(t *testing.T) {
		carol, dan := w.ready(t, "carol"), w.ready(t, "dan")
		carol.mustSend("dan", "hey dan")
		dan.mustSend("carol", "hey carol")
		expectTexts(t, dan.pull("carol"), "hey dan")
		expectTexts(t, carol.pull("dan"), "hey carol")
		for i := 0; i < 6; i++ {
			carol.mustSend("dan", fmt.Sprintf("c%d", i))
			dan.mustSend("carol", fmt.Sprintf("d%d", i))
			expectTexts(t, dan.pull("carol"), fmt.Sprintf("c%d", i))
			expectTexts(t, carol.pull("dan"), fmt.Sprintf("d%d", i))
		}
	})

	t.Run("errors are told apart instead of being called 'queued'", func(t *testing.T) {
		a := alice.app()
		_, err := a.send("nosuchuser", "hello?")
		if err == nil || !strings.Contains(err.Error(), "no itter user") {
			t.Fatalf("unknown user: %v", err)
		}
		w.mem.AddUser("nodms")
		_, err = a.send("nodms", "hello?")
		if err == nil || !strings.Contains(err.Error(), "has not set up DMs") {
			t.Fatalf("user without DMs: %v", err)
		}
		_, err = a.send("alice", "me?")
		if err == nil || !strings.Contains(err.Error(), "yourself") {
			t.Fatalf("self: %v", err)
		}
		_, err = a.send("bob", strings.Repeat("x", api.MaxTextLen+1))
		if err == nil || !strings.Contains(err.Error(), "too long") {
			t.Fatalf("too long: %v", err)
		}
		_, err = a.send("../../etc", "x")
		if err == nil || !strings.Contains(err.Error(), "not a valid") {
			t.Fatalf("bad name: %v", err)
		}
		if len(a.v.OutboxSnapshot()) != 0 || len(a.v.GetMessages("nosuchuser")) != 0 {
			t.Fatal("a message that could not be sent was stored as if it had been")
		}
		// first contact while offline cannot be queued, and says so
		down := &flaky{match: func(r *http.Request) bool { return true }}
		withNetwork(down, func() {
			_, err = alice.app().send("carol", "first contact, offline")
			if err == nil || !strings.Contains(err.Error(), "could not be queued") {
				t.Fatalf("offline first contact: %v", err)
			}
		})
	})

	t.Run("one-shot commands print what happened", func(t *testing.T) {
		alice.use()
		out, err := capture(func() error { return cmdDM([]string{"@bob", "from", "the", "command", "line"}) })
		if err != nil || !strings.Contains(out, "Sent to @bob") {
			t.Fatalf("%q, %v", out, err)
		}
		_, err = capture(func() error { return cmdDM([]string{"@nosuchuser", "x"}) })
		if err == nil || !strings.Contains(err.Error(), "no itter user") {
			t.Fatalf("got %v", err)
		}
		bob.use()
		out, err = capture(func() error { return cmdRead(nil) })
		if err != nil || !strings.Contains(out, "from the command line") || !strings.Contains(out, "@alice") {
			t.Fatalf("read: %q, %v", out, err)
		}
		out, _ = capture(func() error { return cmdRead(nil) })
		if !strings.Contains(out, "No new messages") {
			t.Fatalf("second read: %q", out)
		}
		out, _ = capture(func() error { return cmdRead([]string{"@alice", "2"}) })
		if strings.Count(out, "\n") < 2 || !strings.Contains(out, "from the command line") {
			t.Fatalf("history: %q", out)
		}
		out, _ = capture(cmdContacts)
		if !strings.Contains(out, "@alice") || !strings.Contains(out, "unverified") {
			t.Fatalf("contacts: %q", out)
		}
		// dm catches up before it sends: the reply is not missed, and the
		// session leaves the phase where every message carries the handshake.
		alice.mustSend("bob", "one more for later")
		bob.use()
		out, err = capture(func() error { return cmdDM([]string{"@alice", "answering"}) })
		if err != nil || !strings.Contains(out, "Sent to @alice") || !strings.Contains(out, "new messages") {
			t.Fatalf("dm with mail waiting: %q, %v", out, err)
		}
		out, _ = capture(func() error { return cmdRead(nil) })
		if !strings.Contains(out, "one more for later") || strings.Contains(out, "from the command line") {
			t.Fatalf("read must show exactly what is new: %q", out)
		}
		// What I sent myself is not news.
		if _, err = capture(func() error { return cmdDM([]string{"@alice", "and", "another"}) }); err != nil {
			t.Fatal(err)
		}
		if out, _ = capture(func() error { return cmdRead(nil) }); !strings.Contains(out, "No new messages") {
			t.Fatalf("read after my own message: %q", out)
		}
		// Verifying asks for the number to be confirmed; no answer, no mark.
		out, err = capture(func() error { return cmdTrust([]string{"@alice"}, "verify") })
		if err == nil || !strings.Contains(out, "Safety number with @alice") {
			t.Fatalf("verify without confirmation: %q, %v", out, err)
		}
		if info, _ := bob.app().v.ContactInfo("alice"); info.Verified {
			t.Fatal("marked as verified without confirmation")
		}
		out, err = capture(cmdStatus)
		for _, want := range []string{"Account:      @bob", "connected, it knows this device", "Contacts:     1, 1 not verified"} {
			if err != nil || !strings.Contains(out, want) {
				t.Fatalf("status lacks %q: %q, %v", want, out, err)
			}
		}
		if strings.Contains(out, "Unread") || strings.Contains(out, "Not sent yet") {
			t.Fatalf("status reports work that is not there: %q", out)
		}
	})
}

func TestHostileInput(t *testing.T) {
	w := newWorld(t)
	alice, bob, mallory := w.ready(t, "alice"), w.ready(t, "bob"), w.ready(t, "mallory")
	alice.mustSend("bob", "hi")
	bob.pull("alice")
	bob.mustSend("alice", "hey")
	alice.pull("bob")

	t.Run("undecryptable messages are reported, not dropped silently", func(t *testing.T) {
		garbage := func(a *app, n int) []byte {
			raw, _ := json.Marshal(pqc.WireMsg{Type: pqc.WireEnvelope, From: a.v.Username, Dev: a.v.DeviceID(),
				Payload: json.RawMessage(fmt.Sprintf(`{"v":2,"env":"AAA%d"}`, n))})
			return raw
		}
		_, bobID := bob.app().v.Me()
		to := pqc.IdentityID(bobID.Pub.Encode())
		// From a contact there is a session with: the session may be broken.
		for i := 0; i < 3; i++ {
			if err := post(alice.app(), "bob", garbage(alice.app(), i), to); err != nil {
				t.Fatal(err)
			}
		}
		got := bob.pull("alice")
		if len(texts(got)) != 0 || !strings.Contains(notices(got), "3 message(s) from @alice could not be decrypted") {
			t.Fatalf("got %q", got)
		}
		if strings.Count(notices(got), "could not be decrypted") != 1 {
			t.Fatalf("expected one notice for the batch, got %q", got)
		}
		// From someone there never was a session with: `reset` would be the
		// wrong advice, there is nothing to reset.
		for i := 0; i < 3; i++ {
			if err := post(mallory.app(), "bob", garbage(mallory.app(), i), to); err != nil {
				t.Fatal(err)
			}
		}
		got = bob.pull("mallory")
		if len(texts(got)) != 0 || strings.Count(notices(got), "3 message(s) from @mallory could not be read") != 1 ||
			strings.Contains(notices(got), "reset") {
			t.Fatalf("got %q", got)
		}
		// The conversation with alice still works.
		alice.mustSend("bob", "still here")
		expectTexts(t, bob.pull("alice"), "still here")
	})

	t.Run("terminal escape sequences and bidi tricks never reach the screen", func(t *testing.T) {
		evil := "hi\x1b]52;c;ZXZpbA==\x07\x1b[2J\u202eevil\u2066 there\x00\u009b31m"
		a := alice.app()
		err := a.v.Update(func() error { // a modified client that does not clean its own messages
			return queue(a, "bob", "evil", pqc.PackInner(evil))
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.flush(); err != nil {
			t.Fatal(err)
		}
		got := bob.pull("alice")
		if len(got) != 1 || strings.ContainsAny(got[0], "\x1b\x07\x00\u202e\u2066\u009b") {
			t.Fatalf("stored text still contains control characters: %q", got)
		}
		line := strings.Join(formatEetLines("@alice", false, vault.ChatMsg{Text: evil}, labelWidth("@alice"), 100), "\n")
		line = strings.NewReplacer(FgCyan, "", Reset, "", FgBrightBlk, "").Replace(line)
		if strings.ContainsAny(line, "\x1b\x07\x00\u202e\u2066\u009b") {
			t.Fatalf("rendered line contains control characters: %q", line)
		}
	})

	t.Run("a sender cannot place messages in the past or the future", func(t *testing.T) {
		a := alice.app()
		for _, ts := range []int64{1, time.Now().Unix() + 1e6} {
			err := a.v.Update(func() error {
				inner, _ := json.Marshal(pqc.InnerMsg{TS: ts, Text: fmt.Sprintf("ts %d", ts)})
				return queue(a, "bob", randID(), inner)
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		_ = a.flush()
		bob.pull("alice")
		msgs := bob.app().v.GetMessages("alice")
		now := time.Now().Unix()
		for i := 1; i < len(msgs); i++ {
			if msgs[i].TS < msgs[i-1].TS || msgs[i].TS > now+1 {
				t.Fatalf("message %d has timestamp %d (previous %d, now %d)", i, msgs[i].TS, msgs[i-1].TS, now)
			}
		}
	})

	t.Run("a replayed handshake cannot resurrect a session", func(t *testing.T) {
		newbie := w.ready(t, "newbie")
		n := newbie.app()
		_, id := n.v.Me()
		bun := firstBundle(t, n.rc, "bob") // no one-time prekey: the replayable kind
		sess, err := pqc.Initiate(id, "newbie", bun)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := sess.Seal("newbie", pqc.PackInner("original"))
		raw := rawWire(n, wire)
		toID := pqc.IdentityID(bun.Identity)
		if err := post(n, "bob", raw, toID); err != nil {
			t.Fatal(err)
		}
		expectTexts(t, bob.pull("newbie"), "original")
		b := bob.app()
		_ = b.v.Update(func() error { b.v.ResetSessions("newbie"); return nil }) // the session ages out
		raw2 := append(append([]byte{}, raw[:len(raw)-1]...), ' ', '}')          // same handshake, different bytes
		if err := post(n, "bob", raw2, toID); err != nil {
			t.Fatal(err)
		}
		if got := bob.pull("newbie"); len(texts(got)) != 0 {
			t.Fatalf("a replayed handshake was accepted: %q", got)
		}
		if bob.app().v.HasSession("newbie") {
			t.Fatal("the replay resurrected a session")
		}
	})
}

func TestIdentityChange(t *testing.T) {
	w := newWorld(t)

	// pair returns two users who have talked both ways.
	pair := func(t *testing.T, x, y string) (*user, *user) {
		a, b := w.ready(t, x), w.ready(t, y)
		a.mustSend(y, "hi")
		b.pull(x)
		b.mustSend(x, "hey")
		a.pull(y)
		return a, b
	}
	reinstall := func(t *testing.T, u *user) {
		t.Helper()
		if _, err := u.burn(); err != nil {
			t.Fatal(err)
		}
		if _, err := u.setup(); err != nil {
			t.Fatal(err)
		}
	}

	// inject puts a message straight into the relay's store, the way a relay
	// that does not check senders (buggy or hostile) would deliver it.
	inject := func(t *testing.T, to, from string, raw []byte) {
		t.Helper()
		var wm pqc.WireMsg
		if err := json.Unmarshal(raw, &wm); err != nil {
			t.Fatal(err)
		}
		first, _, _ := w.mem.DeviceIDs("mem-" + to) // the first device's ID is the identity's
		if stored, _ := w.mem.PutMessages("mem-"+to, from, map[string][]byte{first: raw}, 100); !stored {
			t.Fatal("could not inject")
		}
	}
	sealed := func(t *testing.T, a *app, to, text string) []byte {
		t.Helper()
		var raw []byte
		err := a.v.Update(func() error {
			wire, _, err := a.v.Seal(to, a.v.Reach(to)[0], pqc.PackInner(text))
			if err != nil {
				return err
			}
			raw, _ = json.Marshal(wire)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	t.Run("sender learns at once that the recipient reinstalled", func(t *testing.T) {
		alice, bob := pair(t, "alice", "bob")
		reinstall(t, bob)
		_, bobID := bob.app().v.Me()
		a := alice.app()
		sn := a.safetyNumber(bobID.Pub.Encode())
		// The one-shot command says what happened and what to do about it.
		printed, err := capture(func() error { return cmdDM([]string{"@bob", "are", "you", "still", "there?"}) })
		if err == nil || !strings.Contains(err.Error(), "NOT delivered to @bob") {
			t.Fatalf("want a failure (the old identity is gone), got %v", err)
		}
		if !strings.Contains(printed, "IDENTITY CHANGED") || !strings.Contains(printed, sn) || !strings.Contains(printed, "accept @bob") {
			t.Fatalf("the failure does not explain itself:\n%s", printed)
		}
		a = alice.app()
		all := strings.Join(render(a.v.GetMessages("bob")), "\n")
		if !strings.Contains(all, "NOT delivered") || strings.Count(all, "IDENTITY CHANGED") != 1 || !strings.Contains(all, sn) {
			t.Fatalf("want a failure notice and one identity-change notice with the new safety number:\n%s", all)
		}
		if got := bob.pull("alice"); len(got) != 0 {
			t.Fatalf("bob received something encrypted for his old identity: %q", got)
		}
		// Nothing goes to the new identity before alice says so — not even
		// for a contact she never verified.
		if _, err := alice.app().send("bob", "second try"); err == nil || !strings.Contains(err.Error(), "accept @bob") {
			t.Fatalf("send before accept: %v", err)
		}
		if n := w.mem.Pending("bob"); n != 0 {
			t.Fatalf("%d message(s) left for the unaccepted identity", n)
		}
		msg, err := alice.app().accept("bob")
		if err != nil || !strings.Contains(msg, sn) {
			t.Fatalf("accept: %q, %v", msg, err)
		}
		alice.mustSend("bob", "second try")
		expectTexts(t, bob.pull("alice"), "second try")
		if all := strings.Join(render(alice.app().v.GetMessages("bob")), "\n"); strings.Count(all, "IDENTITY CHANGED") != 1 {
			t.Fatalf("the change must be announced exactly once:\n%s", all)
		}
	})

	t.Run("the old identity cannot speak any more, even with its old session", func(t *testing.T) {
		alice, bob := pair(t, "carol", "dave")
		old := bob.app()
		stolen := sealed(t, old, "carol", "send the money to account 1234") // a thief with Bob's old device
		stolen2 := sealed(t, old, "carol", "hurry")
		reinstall(t, bob)
		bob.mustSend("carol", "new phone")
		got := alice.pull("dave")
		if len(texts(got)) != 0 || strings.Count(notices(got), "IDENTITY CHANGED") != 1 {
			t.Fatalf("want the change announced and nothing shown, got %q", got)
		}
		_, newID := bob.app().v.Me()
		if info, _ := alice.app().v.ContactInfo("dave"); pqc.IdentityEqual(info.Identity, newID.Pub.Encode()) || info.Held != 1 {
			t.Fatalf("the contact switched identity without the user: %+v", info)
		}
		// The relay refuses the old identity. Even if it did not, the client
		// shows nothing in its name once the relay lists another one...
		inject(t, "carol", "dave", stolen)
		got = alice.pull("dave")
		if len(texts(got)) != 0 || !strings.Contains(notices(got), "does not list") {
			t.Fatalf("a message from the retired identity while the change is pending: %q", got)
		}
		// ...and after the user accepted the new one, the old one is gone for good.
		if _, err := alice.app().accept("dave"); err != nil {
			t.Fatal(err)
		}
		all := render(alice.app().v.GetMessages("dave"))
		expectTexts(t, all[len(all)-1:], "new phone")
		inject(t, "carol", "dave", stolen2)
		if got = alice.pull("dave"); len(texts(got)) != 0 {
			t.Fatalf("a message from the retired identity was shown: %q", got)
		}
		if info, _ := alice.app().v.ContactInfo("dave"); !pqc.IdentityEqual(info.Identity, newID.Pub.Encode()) {
			t.Fatal("alice's contact fell back to the old identity")
		}
		alice.mustSend("dave", "got it")
		expectTexts(t, bob.pull("carol"), "got it")
	})

	t.Run("verified contact: the new identity is held until accepted", func(t *testing.T) {
		alice, bob := pair(t, "erin", "frank")
		alice.use()
		if out, err := capture(func() error { return cmdTrust([]string{"@frank", "--yes"}, "verify") }); err != nil || !strings.Contains(out, "verified for safety number") {
			t.Fatalf("%q, %v", out, err)
		}
		reinstall(t, bob)
		bob.mustSend("erin", "it's me, new phone")
		bob.mustSend("erin", "hello?")
		got := alice.pull("frank")
		_, newID := bob.app().v.Me()
		sn := alice.app().safetyNumber(newID.Pub.Encode())
		if len(texts(got)) != 0 || strings.Count(notices(got), "IDENTITY CHANGED") != 1 ||
			!strings.Contains(notices(got), "the one you verified") || !strings.Contains(notices(got), sn) {
			t.Fatalf("want one notice with the new safety number and no text, got %q", got)
		}
		// Nothing goes out to the unaccepted identity either.
		_, err := alice.app().send("frank", "who is this?")
		if err == nil || !strings.Contains(err.Error(), "accept @frank") {
			t.Fatalf("send to a blocked identity: %v", err)
		}
		// The report shows both safety numbers.
		rep := strings.Join(alice.app().safetyReport("frank"), "\n")
		if !strings.Contains(rep, "DIFFERENT identity") || !strings.Contains(rep, sn) {
			t.Fatalf("safety report:\n%s", rep)
		}
		// Accept: the held messages appear, the contact is unverified again.
		msg, err := alice.app().accept("frank")
		if err != nil || !strings.Contains(msg, "2 held message(s)") || !strings.Contains(msg, sn) {
			t.Fatalf("accept: %q, %v", msg, err)
		}
		a := alice.app()
		all := render(a.v.GetMessages("frank"))
		expectTexts(t, all[len(all)-2:], "it's me, new phone", "hello?")
		if info, _ := a.v.ContactInfo("frank"); info.Verified || info.Held != 0 || len(info.Pending) != 0 {
			t.Fatalf("after accept: %+v", info)
		}
		alice.mustSend("frank", "welcome back")
		expectTexts(t, bob.pull("erin"), "welcome back")
	})

	t.Run("a stranger is only believed if the relay lists the identity that wrote", func(t *testing.T) {
		alice := w.ready(t, "ivy")
		ghost := w.ready(t, "jack") // jack's first identity writes to ivy...
		g := ghost.app()
		_, gid := g.v.Me()
		sess, err := pqc.Initiate(gid, "jack", firstBundle(t, g.rc, "ivy"))
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := sess.Seal("jack", pqc.PackInner("from the identity jack gave up"))
		raw := rawWire(g, wire)
		reinstall(t, ghost) // ...and is released before ivy reads it
		inject(t, "ivy", "jack", raw)
		got := alice.pull("jack")
		if len(texts(got)) != 0 || !strings.Contains(notices(got), "does not list") {
			t.Fatalf("got %q", got)
		}
		if _, known := alice.app().v.ContactInfo("jack"); known {
			t.Fatal("an unlisted identity became a contact")
		}
		// The identity the relay does list is taken on first use, no questions.
		ghost.mustSend("ivy", "hi, it's jack")
		got = alice.pull("jack")
		expectTexts(t, got, "hi, it's jack")
		if !strings.Contains(notices(got), "New conversation") {
			t.Fatalf("no first-contact notice: %q", got)
		}
		_, jid := ghost.app().v.Me()
		if info, known := alice.app().v.ContactInfo("jack"); !known || !pqc.IdentityEqual(info.Identity, jid.Pub.Encode()) {
			t.Fatal("ivy did not remember jack's listed identity")
		}
	})

	t.Run("a long first burst from a new contact arrives completely", func(t *testing.T) {
		alice, bob := w.ready(t, "kim"), w.ready(t, "lars")
		var wantTexts []string
		for i := 0; i < 14; i++ { // more than can be held aside
			text := fmt.Sprintf("burst %d", i)
			bob.mustSend("kim", text)
			wantTexts = append(wantTexts, text)
		}
		expectTexts(t, alice.pull("lars"), wantTexts...)
	})

	t.Run("a handshake in a wrong name is not believed", func(t *testing.T) {
		alice, mallory := w.ready(t, "nina"), w.ready(t, "oscar")
		w.ready(t, "paul")
		m := mallory.app()
		_, mid := m.v.Me()
		// Signed by oscar's identity for the name "oscar", but filed under paul.
		sess, err := pqc.Initiate(mid, "oscar", firstBundle(t, m.rc, "nina"))
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := sess.Seal("paul", pqc.PackInner("it's paul, honest"))
		raw := rawWire(m, wire)
		inject(t, "nina", "paul", raw)
		got := alice.pull("paul")
		if len(texts(got)) != 0 {
			t.Fatalf("a handshake signed for another account name was accepted: %q", got)
		}
		if _, known := alice.app().v.ContactInfo("paul"); known {
			t.Fatal("the forged handshake created a contact")
		}
	})

	t.Run("reset starts a fresh session on both sides", func(t *testing.T) {
		alice, bob := pair(t, "gina", "hank")
		msg, err := alice.app().reset("hank")
		if err != nil || !strings.Contains(msg, "fresh one is set up") {
			t.Fatalf("%q, %v", msg, err)
		}
		got := bob.pull("gina")
		if len(texts(got)) != 0 || !strings.Contains(notices(got), "fresh session") {
			t.Fatalf("bob got %q", got)
		}
		bob.mustSend("gina", "after reset")
		expectTexts(t, alice.pull("hank"), "after reset")
		alice.mustSend("hank", "all good")
		expectTexts(t, bob.pull("gina"), "all good")
	})
}

func TestPreKeyMaintenance(t *testing.T) {
	w := newWorld(t)
	alice := w.ready(t, "alice")
	a := alice.app()
	count := func() int {
		n, err := a.rc.KeyCount(a.auth())
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() != otpkBatch {
		t.Fatalf("%d one-time prekeys after setup, want %d", count(), otpkBatch)
	}
	for count() >= otpkLow { // others start conversations with alice
		if _, err := w.mem.ClaimOTPK("mem-alice", a.v.DeviceID()); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.maintain(); err != nil || count() >= otpkLow {
		t.Fatal("maintenance should not ask the relay again so soon after setup")
	}
	_ = a.v.Update(func() error { a.v.SetKeyCheck(0); return nil })
	if err := a.maintain(); err != nil {
		t.Fatal(err)
	}
	if count() < otpkBatch {
		t.Fatalf("one-time prekeys were not topped up: %d", count())
	}
	// An old signed prekey is rotated; the previous one still answers handshakes in flight.
	oldSPK := a.v.LatestSPK()
	bob := w.ready(t, "bob")
	b := bob.app()
	_, bid := b.v.Me()
	bun := firstBundle(t, b.rc, "alice")
	sess, err := pqc.Initiate(bid, "bob", bun)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.v.Update(func() error {
		a.v.LatestSPK().Created = time.Now().Add(-8 * 24 * time.Hour).Unix()
		a.v.SetKeyCheck(0)
		return nil
	})
	if err := a.maintain(); err != nil {
		t.Fatal(err)
	}
	if a.v.LatestSPK().ID == oldSPK.ID {
		t.Fatal("the signed prekey was not rotated")
	}
	fresh := firstBundle(t, b.rc, "alice")
	if fresh.SPK.ID != a.v.LatestSPK().ID {
		t.Fatal("the relay does not serve the new signed prekey")
	}
	if _, err := fresh.Verify(); err != nil {
		t.Fatal(err)
	}
	wire, _ := sess.Seal("bob", pqc.PackInner("handshake with the old prekey"))
	if err := post(b, "alice", rawWire(b, wire), pqc.IdentityID(bun.Identity)); err != nil {
		t.Fatal(err)
	}
	expectTexts(t, alice.pull("bob"), "handshake with the old prekey")
}

func TestRelayURL(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://relay.itter.sh":   true,
		"http://127.0.0.1:8080":    true,
		"http://localhost:8080/":   true,
		"http://[::1]:8080":        true,
		"http://relay.itter.sh":    false,
		"http://192.168.1.10:8080": false,
		"ftp://x":                  false,
		"relay.itter.sh":           false,
	} {
		t.Setenv("ITTER_RELAY", url)
		_, err := relayURL()
		if (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", url, err, ok)
		}
	}
	t.Setenv("ITTER_RELAY", "http://relay.lan:8080")
	t.Setenv("ITTER_ALLOW_HTTP", "1")
	if _, err := relayURL(); err != nil {
		t.Errorf("explicit opt-in refused: %v", err)
	}
}

func TestCleanAndWrap(t *testing.T) {
	if got := clean("a\x1b[31mb\u202ec\td\ne\u0085f"); got != "a[31mbc d ef" {
		t.Fatalf("%q", got)
	}
	for _, l := range wrap("short words and https://example.com/a/very/long/url/that/does/not/fit/on/one/line ok", 20) {
		if len(l) > 20 {
			t.Fatalf("line too long: %q", l)
		}
	}
	if got := wrap("", 10); len(got) != 1 || got[0] != "" {
		t.Fatalf("%q", got)
	}
	if got := wrap("日本語のテキストです", 6); len(got) < 3 {
		t.Fatalf("wide characters not wrapped by width: %q", got)
	}
}
