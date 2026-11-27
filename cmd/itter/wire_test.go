package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"itter-cli/internal/api"
	"itter-cli/internal/relay"
)

// What goes over the wire, seen from the wire: the tests here record every
// request the real commands make and then play the part of someone who can
// read the connection. The threat model says such a someone exists (SSH and
// TLS rest on what it assumes broken), so nothing they see may be of use.

type recorded struct {
	method, path string
	header       http.Header
	body         []byte
}

type wiretap struct {
	sync.Mutex
	reqs []recorded
}

func (wt *wiretap) see(r *http.Request, body []byte) {
	wt.Lock()
	defer wt.Unlock()
	wt.reqs = append(wt.reqs, recorded{r.Method, r.URL.RequestURI(), r.Header.Clone(), bytes.Clone(body)})
}

func (wt *wiretap) all() []recorded {
	wt.Lock()
	defer wt.Unlock()
	return append([]recorded(nil), wt.reqs...)
}

// count says how many recorded requests were for method and a path prefix.
func (wt *wiretap) count(method, prefix string) int {
	n := 0
	for _, r := range wt.all() {
		if r.method == method && strings.HasPrefix(r.path, prefix) {
			n++
		}
	}
	return n
}

// replay sends a recorded request again, byte for byte.
func (w *world) replay(t *testing.T, r recorded) (int, string) {
	t.Helper()
	req, err := http.NewRequest(r.method, w.ts.URL+r.path, bytes.NewReader(r.body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = r.header.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// everyEncoding returns a secret the ways it could plausibly travel.
func everyEncoding(secret []byte) map[string][]byte {
	return map[string][]byte{
		"raw":          secret,
		"hex":          []byte(hex.EncodeToString(secret)),
		"base64":       []byte(base64.StdEncoding.EncodeToString(secret)),
		"base64 (url)": []byte(base64.RawURLEncoding.EncodeToString(secret)),
		"as shown":     []byte(api.FormatRecovery(secret)),
	}
}

func TestNothingOnTheWireCanBeUsedAgain(t *testing.T) {
	w := newWorld(t)
	tap := &wiretap{}
	w.mu.Lock()
	w.tap = tap.see
	w.mu.Unlock()

	alice, bob := w.ready(t, "alice"), w.ready(t, "bob")
	// A few commands, each the way a new `itter` process would run it.
	alice.mustSend("bob", "one")
	alice.mustSend("bob", "two")
	expectTexts(t, bob.pull("alice"), "one", "two")
	bob.mustSend("alice", "three")
	expectTexts(t, alice.pull("bob"), "three")
	alice.use()
	if out, err := capture(cmdStatus); err != nil || !strings.Contains(out, "connected") {
		t.Fatalf("status: %q, %v", out, err)
	}
	if out, err := capture(func() error { return cmdIgnore([]string{"bob"}, true) }); err != nil {
		t.Fatalf("ignore: %q, %v", out, err)
	}
	if out, err := capture(func() error { return cmdIgnore([]string{"bob"}, false) }); err != nil {
		t.Fatalf("unignore: %q, %v", out, err)
	}

	t.Run("one session per device, kept between runs", func(t *testing.T) {
		if n := tap.count("POST", "/v1/session/alice"); n != 1 {
			t.Fatalf("alice's device opened %d sessions for a setup and six commands, want 1", n)
		}
		if n := tap.count("POST", "/v1/session/bob"); n != 1 {
			t.Fatalf("bob's device opened %d sessions, want 1", n)
		}
	})

	session := func(u *user) *relay.Session {
		t.Helper()
		var s relay.Session
		if err := json.Unmarshal(u.app().v.RelaySessionBlob(), &s); err != nil || len(s.Key) == 0 || s.Ticket == "" {
			t.Fatalf("%s has no session in its vault: %v", u.name, err)
		}
		return &s
	}

	t.Run("no secret travels: not the session key, not the recovery code", func(t *testing.T) {
		secrets := map[string][]byte{}
		for _, u := range []*user{alice, bob} {
			code, err := u.app().v.RecoveryCode()
			if err != nil {
				t.Fatal(err)
			}
			for enc, b := range everyEncoding(code) {
				secrets[u.name+"'s recovery code, "+enc] = b
			}
			for enc, b := range everyEncoding(session(u).Key) {
				secrets[u.name+"'s session key, "+enc] = b
			}
		}
		for _, r := range tap.all() {
			var head bytes.Buffer
			_ = r.header.Write(&head)
			for what, secret := range secrets {
				if bytes.Contains(r.body, secret) || bytes.Contains(head.Bytes(), secret) {
					t.Fatalf("%s is in a %s %s", what, r.method, r.path)
				}
			}
			if r.header.Get("Authorization") != "" {
				t.Fatalf("%s %s carries an Authorization header", r.method, r.path)
			}
		}
	})

	t.Run("no request can be sent a second time", func(t *testing.T) {
		authed := 0
		for _, r := range tap.all() {
			switch {
			case r.header.Get(api.SessionHeader) != "":
				authed++
				if code, body := w.replay(t, r); code != http.StatusUnauthorized {
					t.Fatalf("%s %s was accepted a second time: %d %q", r.method, r.path, code, body)
				}
			case strings.HasPrefix(r.path, "/v1/session/"):
				if code, body := w.replay(t, r); code != http.StatusUnauthorized {
					t.Fatalf("a session was opened with a recorded request: %d %q", code, body)
				}
			}
		}
		if authed < 10 {
			t.Fatalf("only %d authenticated requests were seen; the test looks at too little", authed)
		}
		// The replays did no harm: both devices carry on.
		alice.mustSend("bob", "four")
		expectTexts(t, bob.pull("alice"), "four")
	})

	t.Run("what was seen makes no new request either", func(t *testing.T) {
		var seen recorded
		for _, r := range tap.all() {
			if r.header.Get(api.SessionHeader) == session(bob).Ticket && r.method == "GET" {
				seen = r
			}
		}
		if seen.path == "" {
			t.Fatal("no request of bob's was seen")
		}
		// The listener has bob's ticket and a MAC of his. Neither is a key.
		mac, _ := base64.StdEncoding.DecodeString(seen.header.Get(api.AuthHeader))
		for what, key := range map[string][]byte{"a MAC that went by": mac, "the ticket": []byte(session(bob).Ticket)[:32], "nothing": nil} {
			forged := &relay.Session{Ticket: session(bob).Ticket, Key: key}
			for _, try := range []struct{ method, path string }{
				{"GET", "/v1/inbox/bob"},
				{"PUT", "/v1/ignore/bob/alice"},
				{"POST", "/v1/inbox/bob/ack"},
			} {
				req, _ := http.NewRequest(try.method, w.ts.URL+try.path, nil)
				if err := forged.Authorize(req, try.path, nil); err != nil {
					t.Fatal(err)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("%s %s with %s as the key: %d", try.method, try.path, what, resp.StatusCode)
				}
			}
		}
		bob.use()
		out, err := capture(func() error { return cmdIgnore(nil, true) }) // no name: it lists
		if err != nil || strings.Contains(out, "alice") {
			t.Fatalf("bob's ignore list after the attempts: %q, %v", out, err)
		}
	})

	t.Run("a relay that was restarted is no trouble", func(t *testing.T) {
		before := tap.count("POST", "/v1/session/alice")
		old := session(alice)
		w.restart() // no ITTER_TOKEN_KEY: every session is forgotten
		alice.mustSend("bob", "after the restart")
		expectTexts(t, bob.pull("alice"), "after the restart")
		if n := tap.count("POST", "/v1/session/alice") - before; n != 1 {
			t.Fatalf("alice's device opened %d sessions after the restart, want 1", n)
		}
		if now := session(alice); now.Ticket == old.Ticket || bytes.Equal(now.Key, old.Key) {
			t.Fatal("the vault still holds the session the relay forgot")
		}
		alice.mustSend("bob", "and once more")
		if n := tap.count("POST", "/v1/session/alice") - before; n != 1 {
			t.Fatalf("the new session was not kept: %d opened", n)
		}
	})

	t.Run("recovery sends a signature, and a recorded one is spent", func(t *testing.T) {
		code, err := alice.app().v.RecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		lost := *alice
		newDev := &user{t: t, name: "alice", dir: filepath.Join(t.TempDir(), "state"), sock: alice.sock}
		newDev.use()
		r, wr, _ := os.Pipe()
		fmt.Fprintln(wr, api.FormatRecovery(code))
		wr.Close()
		oldIn := os.Stdin
		os.Stdin = r
		before := len(tap.all())
		_, err = capture(func() error { return cmdRecover([]string{"alice"}) })
		os.Stdin = oldIn
		if err != nil {
			t.Fatalf("recover: %v", err)
		}
		var release *recorded
		for _, rq := range tap.all()[before:] {
			if rq.method == "DELETE" && rq.path == "/v1/register" {
				rq := rq
				release = &rq
			}
			for enc, b := range everyEncoding(code) {
				if bytes.Contains(rq.body, b) || strings.Contains(rq.path, string(b)) {
					t.Fatalf("the recovery code (%s) is in a %s %s", enc, rq.method, rq.path)
				}
			}
		}
		if release == nil {
			t.Fatal("no release was sent")
		}
		// alice sets up again; the listener sends the recorded release once more.
		if _, err := newDev.setup(); err != nil {
			t.Fatalf("setup after recovery: %v", err)
		}
		if code, body := w.replay(t, *release); code != http.StatusForbidden {
			t.Fatalf("the recorded release against the new identity: %d %q", code, body)
		}
		if _, err := newDev.app().rc.KeyCount(newDev.app().auth()); err != nil {
			t.Fatalf("the new identity must be untouched: %v", err)
		}
		// The device that was lost is out, session and all.
		_, err = lost.app().pull(0)
		if err == nil || !strings.Contains(explain(err), "no longer knows this device") {
			t.Fatalf("the lost device: %v", err)
		}
	})
}
