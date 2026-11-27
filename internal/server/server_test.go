package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"itter-cli/internal/api"
	"itter-cli/internal/pqc"
	"itter-cli/internal/relay"
)

// --- fixtures (identities are slow to make: SLH-DSA) ---

type acct struct {
	name   string
	id     *pqc.Identity
	signer ssh.Signer
	code   []byte
	spk    *pqc.PreKeyPublic
	spkSig []byte
}

func (a *acct) auth() relay.Auth { return relay.Auth{Username: a.name, ID: a.id} }

var (
	fixOnce sync.Once
	fixIDs  []*pqc.Identity
	fixSPK  []*pqc.PreKey
	fixPub  []*pqc.PreKeyPublic
)

func identities(t testing.TB) {
	fixOnce.Do(func() {
		for i := 0; i < 4; i++ {
			id, err := pqc.GenerateIdentity()
			if err != nil {
				t.Fatal(err)
			}
			spk, pub, err := pqc.GenerateSignedPreKey(id, 1)
			if err != nil {
				t.Fatal(err)
			}
			fixIDs, fixSPK, fixPub = append(fixIDs, id), append(fixSPK, spk), append(fixPub, pub)
		}
	})
}

func edSigner(t testing.TB) ssh.Signer {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func authKey(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

func newAcct(t testing.TB, mem *MemStore, name string, n int) *acct {
	identities(t)
	a := &acct{name: name, id: fixIDs[n], signer: edSigner(t), code: bytes.Repeat([]byte{byte(n + 1)}, 32),
		spk: fixPub[n], spkSig: fixSPK[n].Sig}
	mem.AddUser(name, authKey(a.signer))
	return a
}

func (a *acct) regReq(t testing.TB, signer ssh.Signer) *api.RegReq {
	return a.regReqAt(t, signer, time.Now())
}

// recoveryKeys caches the public key of a recovery code (making one is slow).
var recoveryKeys sync.Map

func recoveryKey(t testing.TB, code []byte) []byte {
	if k, ok := recoveryKeys.Load(string(code)); ok {
		return k.([]byte)
	}
	k, err := pqc.RecoveryPublic(code)
	if err != nil {
		t.Fatal(err)
	}
	recoveryKeys.Store(string(code), k)
	return k
}

func (a *acct) regReqAt(t testing.TB, signer ssh.Signer, when time.Time) *api.RegReq {
	enc := a.id.Pub.Encode()
	hash := recoveryKey(t, a.code)
	payload := api.RegPayload(a.name, enc, hash, when.Unix())
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatal(err)
	}
	idSig, err := a.id.Sign.SignFull(payload, "dm-binding")
	if err != nil {
		t.Fatal(err)
	}
	return &api.RegReq{Username: a.name, Identity: enc, SSHSigs: []api.SSHSig{{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest}},
		IDSig: idSig, RecoveryKey: hash, TS: when.Unix()}
}

// skSigner signs like an OpenSSH FIDO key (sk-ssh-ed25519): the signature
// covers the application, flags and a counter, which travel next to it.
type skSigner struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newSKSigner(t testing.TB) *skSigner {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blob := ssh.Marshal(struct {
		Type string
		Key  []byte
		App  string
	}{"sk-ssh-ed25519@openssh.com", pub, "ssh:"})
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return &skSigner{priv: priv, pub: pk}
}

func (s *skSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *skSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	app, msg := sha256.Sum256([]byte("ssh:")), sha256.Sum256(data)
	const flags, counter = 1, 7
	signed := append(append(app[:], flags, 0, 0, 0, counter), msg[:]...)
	return &ssh.Signature{
		Format: s.pub.Type(),
		Blob:   ed25519.Sign(s.priv, signed),
		Rest:   []byte{flags, 0, 0, 0, counter},
	}, nil
}

func (a *acct) register(t testing.TB, rc *relay.Client) {
	t.Helper()
	if _, err := rc.Register(a.regReq(t, a.signer)); err != nil {
		t.Fatalf("register %s: %v", a.name, err)
	}
	if err := rc.UploadKeys(a.auth(), a.spk, a.spkSig, nil); err != nil {
		t.Fatalf("upload keys %s: %v", a.name, err)
	}
}

func (a *acct) dev() string { return pqc.IdentityID(a.id.Pub.Encode()) }

// authorize makes req a request of a's session with the relay, the way the
// client does it. Tests use it to send requests the client never would.
func authorize(t testing.TB, rc *relay.Client, a *acct, req *http.Request, body []byte) {
	t.Helper()
	sess, err := rc.SessionFor(a.auth())
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Authorize(req, req.URL.RequestURI(), body); err != nil {
		t.Fatal(err)
	}
}

// status sends req and returns the status and body of the answer.
func status(t testing.TB, req *http.Request) (int, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// envelope is a message from a's (first) device; the relay cannot look inside.
func envelope(a *acct) []byte {
	return envelopeAs(a.name, a.dev())
}

func envelopeAs(from, dev string) []byte {
	b, _ := json.Marshal(pqc.WireMsg{Type: pqc.WireEnvelope, From: from, Dev: dev, Payload: json.RawMessage(`{"v":2,"env":"AAAA"}`)})
	return b
}

// send posts one message for the recipient's first device, whose ID is the
// ID of the account identity.
func send(rc *relay.Client, from *acct, to string, raw []byte, toID string) error {
	return rc.Send(from.auth(), to, toID, map[string][]byte{toID: raw})
}

func setup(t testing.TB) (*MemStore, *Server, *httptest.Server, *relay.Client) {
	mem := NewMemStore()
	srv := New(mem, Options{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return mem, srv, ts, relay.New(ts.URL)
}

func want(t *testing.T, what string, err error, status int) {
	t.Helper()
	if got := relay.Status(err); got != status {
		t.Fatalf("%s: got status %d (%v), want %d", what, got, err, status)
	}
}

// --- tests ---

func TestRegistration(t *testing.T) {
	mem, _, _, rc := setup(t)

	t.Run("RSA keys cannot bind an identity", func(t *testing.T) {
		a := newAcct(t, mem, "rsauser", 0)
		rk, _ := rsa.GenerateKey(rand.Reader, 2048)
		rsaSigner, _ := ssh.NewSignerFromKey(rk)
		mem.AddUser("rsauser", authKey(rsaSigner))
		_, err := rc.Register(a.regReq(t, rsaSigner))
		want(t, "RSA-signed binding", err, http.StatusForbidden)
	})

	alice := newAcct(t, mem, "Alice", 0)
	t.Run("first registration, case-insensitive name, idempotent", func(t *testing.T) {
		req := alice.regReq(t, alice.signer)
		req.Username = "alice" // typed in lower case
		name, err := rc.Register(req)
		if err != nil || name != "Alice" {
			t.Fatalf("got %q, %v; want the canonical spelling", name, err)
		}
		if _, err := rc.Register(alice.regReq(t, alice.signer)); err != nil {
			t.Fatalf("re-registering the same identity must succeed: %v", err)
		}
	})

	t.Run("a different identity cannot take the account over", func(t *testing.T) {
		thief := &acct{name: "Alice", id: fixIDs[1], signer: alice.signer, code: bytes.Repeat([]byte{9}, 32)}
		_, err := rc.Register(thief.regReq(t, alice.signer)) // even with the right SSH key
		want(t, "takeover", err, http.StatusConflict)
	})

	t.Run("recovery code releases, wrong code does not", func(t *testing.T) {
		want(t, "wrong code", rc.ReleaseWithCode("alice", bytes.Repeat([]byte{7}, 32)), http.StatusForbidden)

		// What a release with the code looks like on the wire: a signature
		// over this identity and the time. Whoever records it holds nothing
		// that works later or for another identity.
		release := func(ts int64, name string) *http.Request {
			sig, err := pqc.RecoverySign(alice.code, api.RecoverPayload(name, ts))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(api.ReleaseReq{Username: "alice", TS: ts, RecoverySig: sig})
			if bytes.Contains(b, alice.code) || bytes.Contains(b, []byte(api.FormatRecovery(alice.code))) {
				t.Fatal("the recovery code itself is in the request")
			}
			req, _ := http.NewRequest("DELETE", rc.Base+"/v1/register", bytes.NewReader(b))
			return req
		}
		if code, body := status(t, release(time.Now().Add(-time.Hour).Unix(), "alice")); code != http.StatusUnauthorized || body != api.ErrClockSkew {
			t.Fatalf("a release signed an hour ago: %d %q", code, body)
		}
		if code, _ := status(t, release(time.Now().Unix(), "bob")); code != http.StatusForbidden {
			t.Fatalf("a release signed for another account: %d", code)
		}
		stolen := release(time.Now().Unix(), "alice")
		stolenBody, _ := io.ReadAll(stolen.Body)
		var changed api.ReleaseReq
		_ = json.Unmarshal(stolenBody, &changed)
		changed.TS += 5 // the time is signed
		b, _ := json.Marshal(changed)
		later, _ := http.NewRequest("DELETE", rc.Base+"/v1/register", bytes.NewReader(b))
		if code, _ := status(t, later); code != http.StatusForbidden {
			t.Fatalf("a release with another time than signed: %d", code)
		}
		if rec, err := mem.Identity("mem-alice"); err != nil || rec == nil || !bytes.Equal(rec.Identity, alice.id.Pub.Encode()) {
			t.Fatalf("alice must still be registered: %v", err)
		}
		recorded := release(time.Now().Unix(), "alice")
		body, _ := io.ReadAll(recorded.Body)
		again := func() *http.Request {
			req, _ := http.NewRequest("DELETE", rc.Base+"/v1/register", bytes.NewReader(body))
			return req
		}
		if code, _ := status(t, again()); code != http.StatusNoContent {
			t.Fatalf("release with the code: %d", code)
		}

		thief := &acct{name: "Alice", id: fixIDs[1], signer: alice.signer, code: bytes.Repeat([]byte{9}, 32)}
		if _, err := rc.Register(thief.regReq(t, alice.signer)); err != nil {
			t.Fatalf("after a release the account must be free again: %v", err)
		}
		// The recorded release does nothing to the identity that came after.
		if code, _ := status(t, again()); code != http.StatusForbidden {
			t.Fatalf("an old release replayed against a new identity: %d", code)
		}
		want(t, "the old code against the new identity", rc.ReleaseWithCode("alice", alice.code), http.StatusForbidden)
		if rec, err := mem.Identity("mem-alice"); err != nil || rec == nil || !bytes.Equal(rec.Identity, fixIDs[1].Pub.Encode()) {
			t.Fatalf("the new identity must still be there: %v", err)
		}
	})

	t.Run("an old registration cannot be replayed to bind a released identity again", func(t *testing.T) {
		carol := newAcct(t, mem, "carol", 3)
		recorded := carol.regReqAt(t, carol.signer, time.Now().Add(-time.Hour)) // what an eavesdropper kept
		_, err := rc.Register(recorded)
		want(t, "stale registration", err, http.StatusUnauthorized)
		if !relay.Is(err, api.ErrClockSkew) {
			t.Fatalf("a client with a wrong clock must be told so: %v", err)
		}
		forged := carol.regReq(t, carol.signer)
		forged.TS -= 3 // the time is covered by both signatures
		_, err = rc.Register(forged)
		want(t, "registration with a changed time", err, http.StatusForbidden)
		if _, err := rc.Directory("carol"); relay.Status(err) != http.StatusGone {
			t.Fatalf("carol must still have no identity: %v", err)
		}
	})

	t.Run("FIDO security keys (sk-ssh-ed25519) can bind an identity", func(t *testing.T) {
		dora := newAcct(t, mem, "dora", 3)
		sk := newSKSigner(t)
		mem.AddUser("dora", authKey(sk))
		req := dora.regReq(t, sk)
		noRest := *req
		noRest.SSHSigs = []api.SSHSig{{Format: req.SSHSigs[0].Format, Blob: req.SSHSigs[0].Blob}}
		_, err := rc.Register(&noRest)
		want(t, "FIDO signature without its counter data", err, http.StatusForbidden)
		if _, err := rc.Register(req); err != nil {
			t.Fatalf("FIDO-signed binding: %v", err)
		}
	})

	t.Run("signed release, and sessions end with the identity", func(t *testing.T) {
		bob := newAcct(t, mem, "bob", 2)
		bob.register(t, rc)
		tc := relay.New(rc.Base)
		if _, err := tc.Inbox(bob.auth(), 0); err != nil {
			t.Fatal(err)
		}
		stale := &api.ReleaseReq{Username: "bob", TS: time.Now().Add(-time.Hour).Unix()}
		stale.Sig, _ = bob.id.Sign.SignFull(api.ReleasePayload("bob", bob.id.Pub.Encode(), stale.TS), "dm-release")
		b, _ := json.Marshal(stale)
		req, _ := http.NewRequest("DELETE", rc.Base+"/v1/register", bytes.NewReader(b))
		if code, _ := status(t, req); code != http.StatusUnauthorized {
			t.Fatalf("a release signed an hour ago: %d", code)
		}
		if err := rc.Release(bob.auth()); err != nil {
			t.Fatal(err)
		}
		_, err := tc.Inbox(bob.auth(), 0)
		want(t, "session of a released identity", err, http.StatusUnauthorized)
		_, err = relay.New(rc.Base).Inbox(bob.auth(), 0)
		want(t, "a new session for a released identity", err, http.StatusUnauthorized)
	})

	t.Run("concurrent first registrations: exactly one identity wins", func(t *testing.T) {
		mem.AddUser("racer")
		signer := edSigner(t)
		mem.AddUser("racer", authKey(signer))
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := 0; i < 2; i++ {
			a := &acct{name: "racer", id: fixIDs[i], signer: signer, code: bytes.Repeat([]byte{1}, 32)}
			req := a.regReq(t, signer)
			wg.Add(1)
			go func(i int) { defer wg.Done(); _, errs[i] = rc.Register(req) }(i)
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else {
				want(t, "loser", err, http.StatusConflict)
			}
		}
		if ok != 1 {
			t.Fatalf("%d registrations succeeded, want exactly 1", ok)
		}
	})
}

// tap records everything a client sends and receives, like someone who can
// read the connection.
type tap struct {
	mu   sync.Mutex
	seen [][]byte
}

func (tp *tap) RoundTrip(req *http.Request) (*http.Response, error) {
	var sent bytes.Buffer
	_ = req.Header.Write(&sent)
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(b))
		sent.Write(b)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(got))
	tp.mu.Lock()
	tp.seen = append(tp.seen, sent.Bytes(), got)
	tp.mu.Unlock()
	return resp, nil
}

func TestAuthentication(t *testing.T) {
	mem, srv, ts, rc := setup(t)
	alice := newAcct(t, mem, "alice", 0)
	alice.register(t, rc)

	get := func(path string) *http.Request {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		return req
	}
	clone := func(req *http.Request, method, path string, body []byte) *http.Request {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		r2, _ := http.NewRequest(method, ts.URL+path, rd)
		r2.Header = req.Header.Clone()
		return r2
	}

	t.Run("a request cannot be replayed", func(t *testing.T) {
		req := get("/v1/inbox/alice")
		authorize(t, rc, alice, req, nil)
		for i, wantStatus := range []int{http.StatusOK, http.StatusUnauthorized} {
			if code, _ := status(t, clone(req, "GET", "/v1/inbox/alice", nil)); code != wantStatus {
				t.Fatalf("attempt %d: status %d, want %d", i, code, wantStatus)
			}
		}
	})

	t.Run("what authorises one request authorises no other", func(t *testing.T) {
		for _, c := range []struct {
			what, method, path string
			body               []byte
		}{
			{"another path", "GET", "/v1/keys/alice/count", nil},
			{"another query", "GET", "/v1/inbox/alice?wait=1", nil},
		} {
			req := get("/v1/inbox/alice")
			authorize(t, rc, alice, req, nil) // fresh nonce each time: this is not about replays
			if code, body := status(t, clone(req, c.method, c.path, c.body)); code != http.StatusUnauthorized {
				t.Fatalf("%s: status %d %q", c.what, code, body)
			}
		}
		put, _ := http.NewRequest("PUT", ts.URL+"/v1/ignore/alice/alice", nil)
		authorize(t, rc, alice, put, nil)
		if code, body := status(t, clone(put, "DELETE", "/v1/ignore/alice/alice", nil)); code != http.StatusUnauthorized {
			t.Fatalf("another method: status %d %q", code, body)
		}
		// The body is covered too when there is one.
		ack, _ := json.Marshal(api.AckReq{IDs: []int64{1}})
		req, _ := http.NewRequest("POST", ts.URL+"/v1/inbox/alice/ack", bytes.NewReader(ack))
		authorize(t, rc, alice, req, ack)
		other, _ := json.Marshal(api.AckReq{IDs: []int64{2}})
		if code, _ := status(t, clone(req, "POST", "/v1/inbox/alice/ack", other)); code != http.StatusUnauthorized {
			t.Fatalf("another body under the same MAC: %d", code)
		}
		if code, _ := status(t, clone(req, "POST", "/v1/inbox/alice/ack", ack)); code != http.StatusNoContent {
			t.Fatalf("the request as it was made: %d", code)
		}
	})

	t.Run("a wrong clock gets a clear answer", func(t *testing.T) {
		srv.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
		defer func() { srv.now = time.Now }()
		_, err := rc.Inbox(alice.auth(), 0)
		he, ok := err.(*relay.HTTPError)
		if !ok || he.Status != http.StatusUnauthorized || he.Body != api.ErrClockSkew || he.ServerTime == 0 {
			t.Fatalf("got %v", err)
		}
		_, err = relay.New(ts.URL).Inbox(alice.auth(), 0) // opening a session says the same
		he, ok = err.(*relay.HTTPError)
		if !ok || he.Status != http.StatusUnauthorized || he.Body != api.ErrClockSkew || he.ServerTime == 0 {
			t.Fatalf("opening a session: got %v", err)
		}
	})

	t.Run("reading the connection gives nothing to act with", func(t *testing.T) {
		wire := &tap{}
		tc := relay.New(ts.URL)
		tc.HC = &http.Client{Transport: wire}
		for i := 0; i < 3; i++ {
			if _, err := tc.Inbox(alice.auth(), 0); err != nil {
				t.Fatal(err)
			}
		}
		if len(wire.seen) != 2*4 {
			t.Fatalf("%d messages on the wire, want one session and three requests", len(wire.seen)/2)
		}
		sess, err := tc.SessionFor(alice.auth())
		if err != nil {
			t.Fatal(err)
		}
		// The session key is on neither side of any exchange, in no encoding.
		for _, enc := range [][]byte{sess.Key, []byte(base64.StdEncoding.EncodeToString(sess.Key)),
			[]byte(base64.RawURLEncoding.EncodeToString(sess.Key)), []byte(hex.EncodeToString(sess.Key))} {
			for i, msg := range wire.seen {
				if bytes.Contains(msg, enc) {
					t.Fatalf("the session key is in message %d on the wire", i)
				}
			}
		}
		// What is there: the ticket. It is a name, not a key.
		if !bytes.Contains(wire.seen[2], []byte(sess.Ticket)) {
			t.Fatal("expected the ticket in a request")
		}
		// ...and the MACs of the requests that went by.
		m := regexp.MustCompile(`(?i)` + api.AuthHeader + `: (\S+)`).FindSubmatch(wire.seen[2])
		if m == nil {
			t.Fatal("expected a MAC in a request")
		}
		sentMAC, err := base64.StdEncoding.DecodeString(string(m[1]))
		if err != nil || len(sentMAC) != pqc.SessionKeySize {
			t.Fatalf("the MAC on the wire: %q, %v", m[1], err)
		}
		elsewhere := ticketFor(&principal{user: User{ID: "mem-alice", Name: "alice"}, idID: alice.dev(), dev: alice.dev()}, sess.Expires, strings.Repeat("0", 32))
		for name, key := range map[string][]byte{
			"a made-up key":                  bytes.Repeat([]byte{1}, pqc.SessionKeySize),
			"no key":                         nil,
			"the ticket as a key":            []byte(sess.Ticket)[:pqc.SessionKeySize],
			"a MAC that went by as a key":    sentMAC,
			"the key of another session":     srv.sessionKey(elsewhere),
			"the session key with a bit off": append([]byte{sess.Key[0] ^ 1}, sess.Key[1:]...),
		} {
			forged := &relay.Session{Ticket: sess.Ticket, Key: key}
			req := get("/v1/inbox/alice")
			if err := forged.Authorize(req, "/v1/inbox/alice", nil); err != nil {
				t.Fatal(err)
			}
			if code, body := status(t, req); code != http.StatusUnauthorized || body != api.ErrSessionGone {
				t.Fatalf("%s: status %d %q", name, code, body)
			}
		}
	})

	t.Run("tickets cannot be made up, and sessions end", func(t *testing.T) {
		good := &principal{user: User{ID: "mem-alice", Name: "alice"}, idID: alice.dev(), dev: alice.dev()}
		try := func(ticket string, key []byte) (int, string) {
			req := get("/v1/inbox/alice")
			if err := (&relay.Session{Ticket: ticket, Key: key}).Authorize(req, "/v1/inbox/alice", nil); err != nil {
				t.Fatal(err)
			}
			return status(t, req)
		}
		sid := strings.Repeat("ab", 16)
		// Sanity: a ticket with the relay's own key for it works. Nobody but
		// the relay can compute that key.
		live := ticketFor(good, time.Now().Add(time.Hour).Unix(), sid)
		if code, body := try(live, srv.sessionKey(live)); code != http.StatusOK {
			t.Fatalf("a real session: %d %q", code, body)
		}
		// Changing who the ticket is for changes its key.
		for name, p := range map[string]*principal{
			"another device": {user: good.user, idID: good.idID, dev: strings.Repeat("0", 32)},
			"another user":   {user: User{ID: "mem-bob", Name: "bob"}, idID: good.idID, dev: good.dev},
		} {
			forged := ticketFor(p, time.Now().Add(time.Hour).Unix(), sid)
			if code, body := try(forged, srv.sessionKey(live)); code != http.StatusUnauthorized || body != api.ErrSessionGone {
				t.Fatalf("%s under alice's key: %d %q", name, code, body)
			}
		}
		later := ticketFor(good, time.Now().Add(1000*time.Hour).Unix(), sid)
		if code, body := try(later, srv.sessionKey(live)); code != http.StatusUnauthorized || body != api.ErrSessionGone {
			t.Fatalf("a ticket with a later end under the old key: %d %q", code, body)
		}
		// A session that has run out, even with the right key.
		old := ticketFor(good, time.Now().Add(-time.Minute).Unix(), sid)
		if code, body := try(old, srv.sessionKey(old)); code != http.StatusUnauthorized || body != api.ErrSessionGone {
			t.Fatalf("a session that ran out: %d %q", code, body)
		}
		// A session of a device the account does not have (any more).
		gone := ticketFor(&principal{user: good.user, idID: good.idID, dev: strings.Repeat("0", 32)}, time.Now().Add(time.Hour).Unix(), sid)
		if code, body := try(gone, srv.sessionKey(gone)); code != http.StatusUnauthorized || body != api.ErrUnknownIdentity {
			t.Fatalf("a device that is not on the list: %d %q", code, body)
		}
		for name, ticket := range map[string]string{
			"empty": "", "not base64": "!!!", "too few fields": base64.RawURLEncoding.EncodeToString([]byte("a\nb\nc")),
			"no end": base64.RawURLEncoding.EncodeToString([]byte("mem-alice\nalice\nx\ny\nsoon\nz")),
			"huge":   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("a\n"), 400)),
		} {
			if code, _ := try(ticket, srv.sessionKey(ticket)); code != http.StatusUnauthorized {
				t.Fatalf("%s ticket: %d", name, code)
			}
		}
	})

	t.Run("the client opens a new session when the relay forgot the old one", func(t *testing.T) {
		tc := relay.New(ts.URL)
		if _, err := tc.Inbox(alice.auth(), 0); err != nil {
			t.Fatal(err)
		}
		before, _ := tc.SessionFor(alice.auth())
		old := srv.opt.TokenKey
		srv.opt.TokenKey = bytes.Repeat([]byte{9}, 32) // a restart without ITTER_TOKEN_KEY
		defer func() { srv.opt.TokenKey = old }()
		if _, err := tc.Inbox(alice.auth(), 0); err != nil {
			t.Fatalf("after the relay lost its key: %v", err)
		}
		after, _ := tc.SessionFor(alice.auth())
		if after == before || after.Ticket == before.Ticket || bytes.Equal(after.Key, before.Key) {
			t.Fatal("the session was not replaced")
		}
	})

	t.Run("only the device itself can open a session", func(t *testing.T) {
		bob := newAcct(t, mem, "bob", 1)
		bob.register(t, rc)
		open := func(name string, edit func(req *api.SessionReq, sign func())) (int, string) {
			offer, err := pqc.NewSessionOffer()
			if err != nil {
				t.Fatal(err)
			}
			req := &api.SessionReq{Device: alice.dev(), TS: time.Now().Unix(), Nonce: strings.Repeat("0", 31) + strconv.Itoa(len(name)%10), Offer: offer.Public()}
			sign := func() {
				req.Sig, err = alice.id.Sign.SignFull(api.SessionPayload("alice", req.Device, req.TS, req.Nonce, req.Offer), "relay-session")
				if err != nil {
					t.Fatal(err)
				}
			}
			sign()
			edit(req, sign)
			b, _ := json.Marshal(req)
			hreq, _ := http.NewRequest("POST", ts.URL+"/v1/session/alice", bytes.NewReader(b))
			return status(t, hreq)
		}
		other, _ := pqc.NewSessionOffer()
		for _, c := range []struct {
			name string
			edit func(req *api.SessionReq, sign func())
			want int
		}{
			{"keys swapped in after signing", func(r *api.SessionReq, _ func()) { r.Offer = other.Public() }, http.StatusUnauthorized},
			{"another time than signed", func(r *api.SessionReq, _ func()) { r.TS-- }, http.StatusUnauthorized},
			{"another nonce than signed", func(r *api.SessionReq, _ func()) { r.Nonce = strings.Repeat("f", 32) }, http.StatusUnauthorized},
			{"signed by someone else", func(r *api.SessionReq, _ func()) {
				r.Sig, _ = bob.id.Sign.SignFull(api.SessionPayload("alice", r.Device, r.TS, r.Nonce, r.Offer), "relay-session")
			}, http.StatusUnauthorized},
			{"signed for another purpose", func(r *api.SessionReq, _ func()) {
				r.Sig, _ = alice.id.Sign.SignFull(api.SessionPayload("alice", r.Device, r.TS, r.Nonce, r.Offer), "dm-release")
			}, http.StatusUnauthorized},
			{"without the hash-based part", func(r *api.SessionReq, _ func()) { r.Sig = r.Sig[:pqc.FastSigSize] }, http.StatusBadRequest},
			{"the hash-based part damaged", func(r *api.SessionReq, _ func()) { r.Sig[len(r.Sig)-1] ^= 1 }, http.StatusUnauthorized},
			{"a device the account does not have", func(r *api.SessionReq, sign func()) { r.Device = bob.dev(); sign() }, http.StatusUnauthorized},
			{"an hour ago", func(r *api.SessionReq, sign func()) { r.TS -= 3600; sign() }, http.StatusUnauthorized},
			{"an offer of the wrong size", func(r *api.SessionReq, sign func()) { r.Offer = r.Offer[:100]; sign() }, http.StatusBadRequest},
			{"as it should be", func(*api.SessionReq, func()) {}, http.StatusOK},
		} {
			if code, body := open(c.name, c.edit); code != c.want {
				t.Fatalf("%s: status %d %q, want %d", c.name, code, body, c.want)
			}
		}
		// A recorded request to open a session cannot be sent again...
		offer, _ := pqc.NewSessionOffer()
		req := &api.SessionReq{Device: alice.dev(), TS: time.Now().Unix(), Nonce: strings.Repeat("c", 32), Offer: offer.Public()}
		req.Sig, _ = alice.id.Sign.SignFull(api.SessionPayload("alice", req.Device, req.TS, req.Nonce, req.Offer), "relay-session")
		b, _ := json.Marshal(req)
		var first api.SessionResp
		for i, wantStatus := range []int{http.StatusOK, http.StatusUnauthorized} {
			hreq, _ := http.NewRequest("POST", ts.URL+"/v1/session/alice", bytes.NewReader(b))
			resp, err := http.DefaultClient.Do(hreq)
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				_ = json.NewDecoder(resp.Body).Decode(&first)
			}
			resp.Body.Close()
			if resp.StatusCode != wantStatus {
				t.Fatalf("opening attempt %d: status %d, want %d", i, resp.StatusCode, wantStatus)
			}
		}
		// ...and its answer opens only with the keys that made the offer.
		if secret, err := offer.Open(first.Answer, []byte(first.Ticket)); err != nil {
			t.Fatal(err)
		} else if key, err := pqc.UnwrapSessionKey(secret, []byte(first.Ticket), first.Box); err != nil || !bytes.Equal(key, srv.sessionKey(first.Ticket)) {
			t.Fatalf("the device's own keys must open the answer: %v", err)
		}
		if secret, err := other.Open(first.Answer, []byte(first.Ticket)); err == nil {
			if _, err := pqc.UnwrapSessionKey(secret, []byte(first.Ticket), first.Box); err == nil {
				t.Fatal("someone else's keys opened the answer")
			}
		}
	})

	t.Run("one user's session is useless for another user's inbox", func(t *testing.T) {
		req := get("/v1/inbox/bob")
		authorize(t, rc, alice, req, nil)
		if code, _ := status(t, req); code != http.StatusForbidden {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("a device that keeps opening sessions is slowed down", func(t *testing.T) {
		carol := newAcct(t, mem, "carol", 2)
		carol.register(t, rc)
		srv.mu.Lock()
		srv.limits["session:mem-carol/"+carol.dev()] = &counter{n: limitSessions, reset: time.Now().Add(time.Hour)}
		srv.mu.Unlock()
		_, err := relay.New(ts.URL).Inbox(carol.auth(), 0)
		want(t, "one session too many", err, http.StatusTooManyRequests)
		if _, err := rc.Inbox(carol.auth(), 0); err != nil {
			t.Fatalf("the session it has keeps working: %v", err)
		}
	})
}

func TestMessages(t *testing.T) {
	mem, _, ts, rc := setup(t)
	alice := newAcct(t, mem, "alice", 0)
	bob := newAcct(t, mem, "bob", 1)
	alice.register(t, rc)
	bob.register(t, rc)
	bobID := pqc.IdentityID(bob.id.Pub.Encode())

	t.Run("senders must be who they say they are", func(t *testing.T) {
		resp, err := http.Post(ts.URL+"/v1/msg/bob", "application/json", bytes.NewReader(envelope(alice)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated send: status %d", resp.StatusCode)
		}
		want(t, "spoofed From", send(rc, alice, "bob", envelopeAs("bob", alice.dev()), bobID), http.StatusForbidden)
		if mem.Pending("bob") != 0 {
			t.Fatal("a refused message was stored")
		}
	})

	t.Run("messages for an identity the recipient no longer has are refused", func(t *testing.T) {
		err := send(rc, alice, "bob", envelope(alice), "0123456789abcdef0123456789abcdef")
		if relay.Status(err) != http.StatusConflict || !relay.Is(err, api.ErrIdentityChanged) {
			t.Fatalf("got %v", err)
		}
		mem.AddUser("carol")
		err = send(rc, alice, "carol", envelope(alice), bobID)
		if relay.Status(err) != http.StatusGone || !relay.Is(err, api.ErrNoIdentity) {
			t.Fatalf("got %v", err)
		}
		want(t, "unknown recipient", send(rc, alice, "nobody", envelope(alice), bobID), http.StatusNotFound)
	})

	t.Run("fetch does not delete; ack does, and only your own", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			if err := send(rc, alice, "bob", envelope(alice), bobID); err != nil {
				t.Fatal(err)
			}
		}
		senders, err := rc.Inbox(bob.auth(), 0)
		if err != nil || senders["alice"] != 3 {
			t.Fatalf("senders %v, %v", senders, err)
		}
		first, _ := rc.InboxFrom(bob.auth(), "alice")
		again, _ := rc.InboxFrom(bob.auth(), "alice")
		if len(first) != 3 || len(again) != 3 {
			t.Fatalf("fetching must not delete: %d then %d", len(first), len(again))
		}
		// alice cannot ack (delete) bob's messages
		if err := rc.Ack(alice.auth(), []int64{first[0].ID, first[1].ID}); err != nil {
			t.Fatal(err)
		}
		if mem.Pending("bob") != 3 {
			t.Fatal("another user's ack deleted messages")
		}
		if err := rc.Ack(bob.auth(), []int64{first[0].ID, first[1].ID}); err != nil {
			t.Fatal(err)
		}
		left, _ := rc.InboxFrom(bob.auth(), "alice")
		if len(left) != 1 || left[0].ID != first[2].ID {
			t.Fatalf("after ack: %d left", len(left))
		}
		_ = rc.Ack(bob.auth(), []int64{left[0].ID})
	})

	t.Run("a page is bounded in bytes too, and nothing is skipped", func(t *testing.T) {
		big := func(i int) []byte { // a first message with its handshake is about this size
			b, _ := json.Marshal(pqc.WireMsg{Type: pqc.WireInitial, From: "alice", Dev: alice.dev(),
				Payload: json.RawMessage(`{"n":` + strconv.Itoa(i) + `,"x":"` + strings.Repeat("A", 200<<10) + `"}`)})
			return b
		}
		const n = 12
		for i := 0; i < n; i++ {
			if err := send(rc, alice, "bob", big(i), bobID); err != nil {
				t.Fatal(err)
			}
		}
		got, pages := 0, 0
		for got < n {
			items, err := rc.InboxFrom(bob.auth(), "alice")
			if err != nil || len(items) == 0 {
				t.Fatalf("page %d: %d items, %v", pages, len(items), err)
			}
			size := 0
			var ids []int64
			for _, it := range items {
				size += len(it.Msg.Payload)
				if !strings.HasPrefix(string(it.Msg.Payload), `{"n":`+strconv.Itoa(got)+`,`) {
					t.Fatalf("message %d is out of order", got)
				}
				got++
				ids = append(ids, it.ID)
			}
			if size > pageBytes {
				t.Fatalf("page %d carries %d bytes", pages, size)
			}
			if err := rc.Ack(bob.auth(), ids); err != nil {
				t.Fatal(err)
			}
			pages++
		}
		if pages < 2 {
			t.Fatalf("%d messages of 200 KB came in %d page(s)", n, pages)
		}
	})

	t.Run("one sender cannot flood one inbox", func(t *testing.T) {
		for i := 0; i < inboxPerPair; i++ {
			if stored, _ := mem.PutMessages("mem-bob", "alice", map[string][]byte{bobID: envelope(alice)}, inboxPerPair); !stored {
				t.Fatalf("inbox full after only %d messages", i)
			}
		}
		err := send(rc, alice, "bob", envelope(alice), bobID)
		if relay.Status(err) != http.StatusTooManyRequests || !relay.Is(err, api.ErrInboxFull) {
			t.Fatalf("got %v", err)
		}
		_ = mem.DeleteIdentity("mem-bob")
		bob.register(t, rc)
	})

	t.Run("oversized and malformed input is rejected", func(t *testing.T) {
		big, _ := json.Marshal(pqc.WireMsg{Type: 2, From: "alice", Payload: json.RawMessage(`"` + strings.Repeat("A", api.MaxMessageSize) + `"`)})
		want(t, "oversized", send(rc, alice, "bob", big, bobID), http.StatusRequestEntityTooLarge)
		want(t, "wrong type", send(rc, alice, "bob", []byte(`{"t":9,"from":"alice","p":{}}`), bobID), http.StatusBadRequest)
		_, err := rc.InboxFrom(bob.auth(), "x,y")
		want(t, "injected sender", err, http.StatusBadRequest)
	})

	t.Run("long-poll returns as soon as a message arrives", func(t *testing.T) {
		done := make(chan time.Duration, 1)
		start := time.Now()
		go func() {
			senders, err := rc.Inbox(bob.auth(), 20)
			if err != nil || senders["alice"] != 1 {
				t.Errorf("long-poll: %v %v", senders, err)
			}
			done <- time.Since(start)
		}()
		time.Sleep(300 * time.Millisecond)
		if err := send(rc, alice, "bob", envelope(alice), bobID); err != nil {
			t.Fatal(err)
		}
		select {
		case d := <-done:
			if d > 3*time.Second {
				t.Fatalf("woke up after %v", d)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("long-poll did not wake up")
		}
		// and it times out quietly when nothing arrives
		items, _ := rc.InboxFrom(bob.auth(), "alice")
		_ = rc.Ack(bob.auth(), []int64{items[0].ID})
		start = time.Now()
		senders, err := rc.Inbox(bob.auth(), 1)
		if err != nil || len(senders) != 0 || time.Since(start) < 900*time.Millisecond {
			t.Fatalf("empty long-poll: %v %v after %v", senders, err, time.Since(start))
		}
	})
}

func TestPreKeys(t *testing.T) {
	mem, _, _, rc := setup(t)
	alice := newAcct(t, mem, "alice", 0)
	bob := newAcct(t, mem, "bob", 1)
	alice.register(t, rc)
	bob.register(t, rc)

	const stock = claimsPerDay + 4
	var otpks []*pqc.PreKeyPublic
	for i := uint32(0); i < stock; i++ {
		_, pub, err := pqc.GenerateOneTimePreKey(100 + i)
		if err != nil {
			t.Fatal(err)
		}
		otpks = append(otpks, pub)
	}
	if err := rc.UploadKeys(bob.auth(), bob.spk, bob.spkSig, otpks); err != nil {
		t.Fatal(err)
	}
	if n, err := rc.KeyCount(bob.auth()); err != nil || n != stock {
		t.Fatalf("count %d, %v", n, err)
	}

	t.Run("the public directory never hands out one-time prekeys", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			d, err := rc.Directory("bob")
			if err != nil || len(d.Devices) != 1 || d.Devices[0].OTPK != nil || d.List != nil {
				t.Fatalf("directory: %+v err=%v", d, err)
			}
			if !bytes.Equal(d.Identity, bob.id.Pub.Encode()) || !bytes.Equal(d.Devices[0].Identity, d.Identity) {
				t.Fatal("the first device's key must be the account identity")
			}
			if _, err := d.Devices[0].Verify(); err != nil {
				t.Fatal(err)
			}
		}
		if n, _ := rc.KeyCount(bob.auth()); n != stock {
			t.Fatalf("public fetches consumed prekeys: %d left", n)
		}
	})

	t.Run("claims are authenticated, unique, and capped per requester", func(t *testing.T) {
		seen := map[uint32]bool{}
		for i := 0; i < claimsPerDay+2; i++ {
			d, err := rc.Claim(alice.auth(), "bob", nil)
			if err != nil || len(d.Devices) != 1 {
				t.Fatal(err)
			}
			b := d.Devices[0]
			if i < claimsPerDay {
				if b.OTPK == nil || seen[b.OTPK.ID] {
					t.Fatalf("claim %d: missing or repeated one-time prekey", i)
				}
				seen[b.OTPK.ID] = true
			} else if b.OTPK != nil {
				t.Fatalf("claim %d: over the daily cap but still got a one-time prekey", i)
			}
		}
		if n, _ := rc.KeyCount(bob.auth()); n != stock-claimsPerDay {
			t.Fatalf("%d left, want %d", n, stock-claimsPerDay)
		}
	})

	t.Run("a prekey not signed by the identity is refused", func(t *testing.T) {
		err := rc.UploadKeys(bob.auth(), alice.spk, alice.spkSig, nil)
		want(t, "foreign signed prekey", err, http.StatusForbidden)
	})

	t.Run("nobody can upload keys for someone else", func(t *testing.T) {
		b, _ := json.Marshal(api.KeysUpload{SPK: alice.spk, SPKSig: alice.spkSig})
		req, _ := http.NewRequest("PUT", rc.Base+"/v1/keys/bob", bytes.NewReader(b))
		authorize(t, rc, alice, req, b)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

func TestRateLimitUsesProxyHeader(t *testing.T) {
	mem := NewMemStore()
	mem.AddUser("alice")
	srv := New(mem, Options{ClientIPHeader: "Fly-Client-IP"})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	get := func(ip string) int {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/keys/alice", nil)
		req.Header.Set("Fly-Client-IP", ip)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < limitIP; i++ {
		if s := get("203.0.113.7"); s == http.StatusTooManyRequests {
			t.Fatalf("limited after %d requests", i)
		}
	}
	if s := get("203.0.113.7"); s != http.StatusTooManyRequests {
		t.Fatalf("expected the busy client to be limited, got %d", s)
	}
	if s := get("203.0.113.8"); s == http.StatusTooManyRequests {
		t.Fatal("another client behind the same proxy was limited too")
	}
}

func TestRateLimitBuckets(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":          "203.0.113.7",
		"::ffff:203.0.113.7":   "203.0.113.7", // IPv4 in disguise is the same client
		"2001:db8:1:2:aaaa::1": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::/64", // same customer, another address
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"not an address":       "not an address",
		"fe80::1%eth0":         "fe80::1%eth0",
	} {
		if got := limitKey(in); got != want {
			t.Errorf("limitKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOperatorRelease(t *testing.T) {
	mem, _, _, rc := setup(t)
	alice := newAcct(t, mem, "alice", 0)
	alice.register(t, rc)
	if err := ReleaseIdentity(mem, "ALICE"); err != nil {
		t.Fatal(err)
	}
	_, err := rc.Directory("alice")
	want(t, "bundle after release", err, http.StatusGone)
	if err := ReleaseIdentity(mem, "nobody"); err == nil {
		t.Fatal("expected an error for an unknown user")
	}
}

// --- linked devices ---

func (a *acct) linkReq(t testing.TB, signer ssh.Signer, secret []byte, dev *pqc.Identity, when time.Time) *api.LinkReq {
	key := dev.Pub.Encode()
	id := pqc.LinkID(secret)
	sig, err := signer.Sign(rand.Reader, api.LinkPayload(a.name, id, key, when.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	return &api.LinkReq{LinkID: id, DeviceKey: key, Tag: pqc.LinkRequestTag(secret, a.name, key),
		SSHSigs: []api.SSHSig{{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest}}, TS: when.Unix()}
}

func (a *acct) list(t testing.TB, v uint64, devs ...*pqc.Identity) *pqc.DeviceList {
	var keys [][]byte
	for _, d := range devs {
		keys = append(keys, d.Pub.Encode())
	}
	l, err := pqc.SignDeviceList(a.id, a.name, v, keys)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestDevices(t *testing.T) {
	mem, _, _, rc := setup(t)
	alice := newAcct(t, mem, "alice", 0)
	bob := newAcct(t, mem, "bob", 1)
	alice.register(t, rc)
	bob.register(t, rc)
	// Alice's second device: a key of its own (fixture 2).
	dev2 := &acct{name: "alice", id: fixIDs[2], spk: fixPub[2], spkSig: fixSPK[2].Sig}
	aliceID := alice.dev()
	secret := bytes.Repeat([]byte{42}, pqc.LinkSecretSize)
	linkID := pqc.LinkID(secret)

	t.Run("a device that is not on the list is nobody", func(t *testing.T) {
		err := rc.UploadKeys(dev2.auth(), dev2.spk, dev2.spkSig, nil)
		want(t, "unlisted device", err, http.StatusUnauthorized)
	})

	t.Run("a link request needs an SSH key of the account and is fresh", func(t *testing.T) {
		stranger := edSigner(t)
		want(t, "foreign SSH key", rc.LinkRequest("alice", alice.linkReq(t, stranger, secret, dev2.id, time.Now())), http.StatusForbidden)
		want(t, "stale", rc.LinkRequest("alice", alice.linkReq(t, alice.signer, secret, dev2.id, time.Now().Add(-time.Hour))), http.StatusUnauthorized)
		mem.AddUser("nodms", authKey(alice.signer))
		nodms := &acct{name: "nodms"}
		want(t, "no first device", rc.LinkRequest("nodms", nodms.linkReq(t, alice.signer, secret, dev2.id, time.Now())), http.StatusGone)
		if err := rc.LinkRequest("alice", alice.linkReq(t, alice.signer, secret, dev2.id, time.Now())); err != nil {
			t.Fatal(err)
		}
		if res, err := rc.LinkResult("alice", linkID); err != nil || res != nil {
			t.Fatalf("no answer yet: %q, %v", res, err)
		}
		_, err := rc.LinkResult("alice", strings.Repeat("0", 32))
		want(t, "unknown link id", err, http.StatusNotFound)
	})

	t.Run("only the account sees its link requests", func(t *testing.T) {
		req, _ := http.NewRequest("GET", rc.Base+"/v1/link/alice/"+linkID, nil)
		authorize(t, rc, bob, req, nil)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("bob read alice's link request: %d", resp.StatusCode)
		}
		info, err := rc.LinkInfo(alice.auth(), linkID)
		if err != nil || !bytes.Equal(info.DeviceKey, dev2.id.Pub.Encode()) ||
			!pqc.TagEqual(info.Tag, pqc.LinkRequestTag(secret, "alice", info.DeviceKey)) {
			t.Fatalf("link info: %v", err)
		}
	})

	t.Run("only the account identity can change the device list", func(t *testing.T) {
		forged, _ := pqc.SignDeviceList(bob.id, "alice", 1, [][]byte{dev2.id.Pub.Encode()})
		want(t, "list signed by someone else", rc.SetDevices(alice.auth(), forged), http.StatusForbidden)
		byDevice, _ := pqc.SignDeviceList(dev2.id, "alice", 1, [][]byte{fixIDs[3].Pub.Encode()})
		want(t, "list signed by a device", rc.SetDevices(alice.auth(), byDevice), http.StatusForbidden)

		l1 := alice.list(t, 1, dev2.id)
		if err := rc.SetDevices(alice.auth(), l1); err != nil {
			t.Fatal(err)
		}
		if err := rc.SetDevices(alice.auth(), l1); err != nil {
			t.Fatalf("the same list again (a lost answer) must be fine: %v", err)
		}
		want(t, "same version, other content", rc.SetDevices(alice.auth(), alice.list(t, 1, fixIDs[3])), http.StatusConflict)
		res, _ := json.Marshal(api.LinkResult{Identity: alice.id.Pub.Encode(), List: l1,
			Tag: pqc.LinkResultTag(secret, "alice", alice.id.Pub.Encode(), dev2.id.Pub.Encode(), 1)})
		if err := rc.LinkAnswer(alice.auth(), linkID, res); err != nil {
			t.Fatal(err)
		}
		got, err := rc.LinkResult("alice", linkID)
		if err != nil || !bytes.Equal(got, res) {
			t.Fatalf("the new device did not get the answer: %v", err)
		}
	})

	t.Run("a listed device publishes its own prekeys, signed by its own key", func(t *testing.T) {
		d, _ := rc.Directory("alice")
		if len(d.Devices) != 1 {
			t.Fatalf("a device without prekeys is not written to yet: %d", len(d.Devices))
		}
		want(t, "prekey signed by another key", rc.UploadKeys(dev2.auth(), alice.spk, alice.spkSig, nil), http.StatusForbidden)
		if err := rc.UploadKeys(dev2.auth(), dev2.spk, dev2.spkSig, nil); err != nil {
			t.Fatal(err)
		}
		d, err := rc.Directory("alice")
		if err != nil || len(d.Devices) != 2 || d.List.Verify(d.Identity, "alice") != nil {
			t.Fatalf("directory: %v", err)
		}
		for i, b := range d.Devices {
			if _, err := b.Verify(); err != nil {
				t.Fatalf("bundle %d: %v", i, err)
			}
			if !bytes.Equal(b.Identity, d.Identity) && !d.List.Has(b.Identity) {
				t.Fatalf("bundle %d is for a device that is not on the signed list", i)
			}
		}
		info, err := rc.Devices(dev2.auth())
		if err != nil || len(info.Devices) != 2 || !info.Devices[0].Primary || !info.Devices[1].Ready {
			t.Fatalf("devices: %+v, %v", info, err)
		}
	})

	both := func(from *acct) map[string][]byte {
		return map[string][]byte{aliceID: envelope(from), dev2.dev(): envelope(from)}
	}

	t.Run("a message has to reach every device, or none", func(t *testing.T) {
		err := send(rc, bob, "alice", envelope(bob), aliceID) // only the first device
		if relay.Status(err) != http.StatusConflict || !relay.Is(err, api.ErrDevicesChanged) {
			t.Fatalf("a send that misses a device: %v", err)
		}
		extra := both(bob)
		extra[pqc.IdentityID(fixIDs[3].Pub.Encode())] = envelope(bob)
		err = rc.Send(bob.auth(), "alice", aliceID, extra)
		if !relay.Is(err, api.ErrDevicesChanged) {
			t.Fatalf("a send to a device that does not exist: %v", err)
		}
		if mem.Pending("alice") != 0 {
			t.Fatal("part of a refused batch was stored")
		}
		if err := rc.Send(bob.auth(), "alice", aliceID, both(bob)); err != nil {
			t.Fatal(err)
		}
		for _, a := range []*acct{alice, dev2} {
			senders, err := rc.Inbox(a.auth(), 0)
			if err != nil || senders["bob"] != 1 {
				t.Fatalf("each device has its own inbox: %v, %v", senders, err)
			}
		}
		// One device fetching and acking leaves the other's copy alone.
		items, _ := rc.InboxFrom(alice.auth(), "bob")
		if len(items) != 1 {
			t.Fatalf("%d items", len(items))
		}
		theirs, _ := rc.InboxFrom(dev2.auth(), "bob")
		if err := rc.Ack(alice.auth(), []int64{items[0].ID, theirs[0].ID}); err != nil {
			t.Fatal(err)
		}
		if left, _ := rc.InboxFrom(dev2.auth(), "bob"); len(left) != 1 {
			t.Fatal("one device deleted another device's message")
		}
		_ = rc.Ack(dev2.auth(), []int64{theirs[0].ID})
	})

	t.Run("one's own devices: everything but the sender", func(t *testing.T) {
		err := rc.Send(alice.auth(), "alice", aliceID, both(alice))
		if !relay.Is(err, api.ErrDevicesChanged) {
			t.Fatalf("a sync that includes the sending device: %v", err)
		}
		if err := rc.Send(alice.auth(), "alice", aliceID, map[string][]byte{dev2.dev(): envelope(alice)}); err != nil {
			t.Fatal(err)
		}
		spoof := map[string][]byte{aliceID: envelopeAs("alice", aliceID)} // dev2 pretending to be the first device
		want(t, "device spoofing", rc.Send(dev2.auth(), "alice", aliceID, spoof), http.StatusForbidden)
		if s, _ := rc.Inbox(dev2.auth(), 0); s["alice"] != 1 {
			t.Fatalf("sync message missing: %v", s)
		}
		items, _ := rc.InboxFrom(dev2.auth(), "alice")
		_ = rc.Ack(dev2.auth(), []int64{items[0].ID})
	})

	t.Run("a linked device can retire itself; the first one cannot", func(t *testing.T) {
		want(t, "first device retiring", rc.RetireDevice(alice.auth()), http.StatusBadRequest)
		if err := rc.Send(bob.auth(), "alice", aliceID, both(bob)); err != nil {
			t.Fatal(err)
		}
		if err := rc.RetireDevice(dev2.auth()); err != nil {
			t.Fatal(err)
		}
		if d, _ := rc.Directory("alice"); len(d.Devices) != 1 {
			t.Fatal("a retired device is still written to")
		}
		if err := send(rc, bob, "alice", envelope(bob), aliceID); err != nil {
			t.Fatalf("after a device retired, the rest must be enough: %v", err)
		}
		if mem.Pending("alice") != 2 { // both for the first device; the retired one's copy is gone
			t.Fatalf("%d waiting", mem.Pending("alice"))
		}
		if err := rc.UploadKeys(dev2.auth(), dev2.spk, dev2.spkSig, nil); err != nil {
			t.Fatalf("a retired device can come back as long as it is listed: %v", err)
		}
	})

	t.Run("taking a device off the list ends it at once", func(t *testing.T) {
		tc := relay.New(rc.Base)
		if _, err := tc.Inbox(dev2.auth(), 0); err != nil {
			t.Fatal(err)
		}
		if err := rc.Send(bob.auth(), "alice", aliceID, both(bob)); err != nil {
			t.Fatal(err)
		}
		if err := rc.SetDevices(alice.auth(), alice.list(t, 2)); err != nil { // an empty list
			t.Fatal(err)
		}
		_, err := tc.Inbox(dev2.auth(), 0)
		want(t, "session of a removed device", err, http.StatusUnauthorized)
		_, err = relay.New(rc.Base).Inbox(dev2.auth(), 0)
		want(t, "a new session for a removed device", err, http.StatusUnauthorized)
		want(t, "an old list again", rc.SetDevices(alice.auth(), alice.list(t, 1, dev2.id)), http.StatusConflict)
		d, _ := rc.Directory("alice")
		if len(d.Devices) != 1 || d.List.Version() != 2 || d.List.Has(dev2.id.Pub.Encode()) {
			t.Fatalf("directory after removal: %d devices, list v%d", len(d.Devices), d.List.Version())
		}
		if mem.Pending("alice") != 3 {
			t.Fatalf("the removed device's messages must be gone, the first device's kept: %d", mem.Pending("alice"))
		}
	})

	t.Run("releasing the identity takes every device with it", func(t *testing.T) {
		if err := rc.SetDevices(alice.auth(), alice.list(t, 3, dev2.id)); err != nil {
			t.Fatal(err)
		}
		_ = rc.UploadKeys(dev2.auth(), dev2.spk, dev2.spkSig, nil)
		if err := rc.Release(alice.auth()); err != nil {
			t.Fatal(err)
		}
		_, err := rc.Inbox(dev2.auth(), 0)
		want(t, "device of a released identity", err, http.StatusUnauthorized)
		_, err = rc.Directory("alice")
		want(t, "directory after release", err, http.StatusGone)
	})
}

func TestIgnoreList(t *testing.T) {
	mem, _, _, rc := setup(t)
	alice := newAcct(t, mem, "alice", 0)
	bob := newAcct(t, mem, "bob", 1)
	alice.register(t, rc)
	bob.register(t, rc)
	_, otpk, _ := pqc.GenerateOneTimePreKey(7)
	if err := rc.UploadKeys(alice.auth(), alice.spk, alice.spkSig, []*pqc.PreKeyPublic{otpk}); err != nil {
		t.Fatal(err)
	}
	aliceID, bobID := alice.dev(), bob.dev()

	if err := send(rc, bob, "alice", envelope(bob), aliceID); err != nil {
		t.Fatal(err)
	}
	want(t, "ignoring oneself", rc.SetIgnore(alice.auth(), "alice", true), http.StatusBadRequest)
	want(t, "ignoring nobody", rc.SetIgnore(alice.auth(), "nosuchuser", true), http.StatusNotFound)
	req, _ := http.NewRequest("PUT", rc.Base+"/v1/ignore/alice/bob", nil)
	authorize(t, rc, bob, req, nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob changed alice's ignore list: %d", resp.StatusCode)
	}

	if err := rc.SetIgnore(alice.auth(), "BOB", true); err != nil { // names ignore case
		t.Fatal(err)
	}
	if err := rc.SetIgnore(alice.auth(), "bob", true); err != nil {
		t.Fatalf("ignoring twice must be fine: %v", err)
	}
	if names, err := rc.Ignored(alice.auth()); err != nil || len(names) != 1 || names[0] != "bob" {
		t.Fatalf("ignored: %v, %v", names, err)
	}
	if mem.Pending("alice") != 0 {
		t.Fatal("what the ignored sender had waiting must go")
	}
	// The ignored sender is not told, and nothing arrives.
	if err := send(rc, bob, "alice", envelope(bob), aliceID); err != nil {
		t.Fatalf("an ignored sender must not see a difference: %v", err)
	}
	if mem.Pending("alice") != 0 {
		t.Fatal("a message from an ignored sender was stored")
	}
	if d, err := rc.Claim(bob.auth(), "alice", nil); err != nil || d.Devices[0].OTPK != nil {
		t.Fatalf("an ignored sender got a one-time prekey: %v", err)
	}
	// Ignoring is one-way.
	if err := send(rc, alice, "bob", envelope(alice), bobID); err != nil || mem.Pending("bob") != 1 {
		t.Fatalf("alice -> bob: %v", err)
	}
	if err := rc.SetIgnore(alice.auth(), "bob", false); err != nil {
		t.Fatal(err)
	}
	if names, _ := rc.Ignored(alice.auth()); len(names) != 0 {
		t.Fatalf("still ignored: %v", names)
	}
	if err := send(rc, bob, "alice", envelope(bob), aliceID); err != nil || mem.Pending("alice") != 1 {
		t.Fatalf("after unignore: %v, %d waiting", err, mem.Pending("alice"))
	}
	if d, _ := rc.Claim(bob.auth(), "alice", nil); d.Devices[0].OTPK == nil {
		t.Fatal("after unignore the one-time prekey must be available")
	}
}

// downStore is a store that can be switched off, like a database that is
// unreachable for a moment.
type downStore struct {
	*MemStore
	down atomic.Bool
}

var errDown = errors.New("store is down")

func (d *downStore) User(name string) (User, error) {
	if d.down.Load() {
		return User{}, errDown
	}
	return d.MemStore.User(name)
}

func (d *downStore) Identity(id string) (*IdentityRecord, error) {
	if d.down.Load() {
		return nil, errDown
	}
	return d.MemStore.Identity(id)
}

func (d *downStore) DeviceIDs(id string) (string, []string, error) {
	if d.down.Load() {
		return "", nil, errDown
	}
	return d.MemStore.DeviceIDs(id)
}

func (d *downStore) Devices(id string) ([]Device, error) {
	if d.down.Load() {
		return nil, errDown
	}
	return d.MemStore.Devices(id)
}

// A device that is told "unknown identity" is told to burn itself and start
// over. That answer must be kept for when it is true.
func TestADatabaseHiccupIsNotAnUnknownDevice(t *testing.T) {
	mem := NewMemStore()
	store := &downStore{MemStore: mem}
	srv := New(store, Options{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	rc := relay.New(ts.URL)
	alice := newAcct(t, mem, "alice", 0)
	alice.register(t, rc)

	store.down.Store(true)
	_, err := rc.Inbox(alice.auth(), 0)
	want(t, "a request while the store is down", err, http.StatusInternalServerError)
	_, err = relay.New(ts.URL).Inbox(alice.auth(), 0)
	want(t, "opening a session while the store is down", err, http.StatusInternalServerError)
	want(t, "uploading keys while the store is down", rc.UploadKeys(alice.auth(), alice.spk, alice.spkSig, nil), http.StatusInternalServerError)
	_, err = rc.Devices(alice.auth())
	want(t, "listing devices while the store is down", err, http.StatusInternalServerError)
	// None of that counted against the address as a failed login.
	srv.mu.Lock()
	failed := srv.limits["authfail:127.0.0.1"]
	srv.mu.Unlock()
	if failed != nil {
		t.Fatalf("%d authentication failures were counted", failed.n)
	}

	store.down.Store(false)
	if _, err := rc.Inbox(alice.auth(), 0); err != nil {
		t.Fatalf("after the store came back: %v", err)
	}
}
