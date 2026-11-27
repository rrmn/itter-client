package relay_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/rrmn/itter-client/internal/gatetest"
	"github.com/rrmn/itter-client/internal/relay"
	"github.com/rrmn/itter-client/internal/server"
)

// world is a relay that can only be reached through a gate, like the one
// next to itter's SSH app.
type world struct {
	ts   *httptest.Server
	gate *gatetest.Gate
	dir  string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ts := httptest.NewUnstartedServer(server.New(server.NewMemStore(), server.Options{}).Handler())
	ts.Listener = server.ProxyListener(ts.Listener)
	ts.Start()
	t.Cleanup(ts.Close)
	gate, err := gatetest.Start("127.0.0.1:0", ts.Listener.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	return &world{ts: ts, gate: gate, dir: t.TempDir()}
}

func (w *world) tunnel() *relay.Tunnel {
	return &relay.Tunnel{Addr: w.gate.Addr, PinFile: filepath.Join(w.dir, "itter_host_key")}
}

// ask makes a request whose answer proves it reached the relay: there is no
// such user, and only the relay can say so.
func ask(rc *relay.Client) error {
	_, err := rc.Directory("nobody")
	return err
}

func wantAnswer(t *testing.T, err error) {
	t.Helper()
	if relay.Status(err) != http.StatusNotFound {
		t.Fatalf("expected the relay's own 404, got: %v", err)
	}
}

func TestRelayThroughTheSSHPort(t *testing.T) {
	w := newWorld(t)
	tun := w.tunnel()
	defer tun.Close()
	rc := relay.NewSSH(tun)
	wantAnswer(t, ask(rc))
	if !strings.Contains(rc.Where(), w.gate.Addr) {
		t.Fatalf("Where() = %q", rc.Where())
	}
	// Everything after that shares the one SSH connection, also at the same time.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ask(rc); relay.Status(err) != http.StatusNotFound {
				t.Errorf("concurrent request: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := w.gate.Logins.Load(); n != 1 {
		t.Fatalf("%d SSH connections for one client, want 1", n)
	}
}

// The client takes the post-quantum hybrid key exchange when the server has
// it, and says which one it ended up with.
func TestKeyExchangeOfThePipe(t *testing.T) {
	w := newWorld(t)
	tun := w.tunnel()
	defer tun.Close()
	if got := tun.KeyExchange(); got != "" {
		t.Fatalf("before any connection: %q", got)
	}
	wantAnswer(t, ask(relay.NewSSH(tun)))
	if got := tun.KeyExchange(); got != "mlkem768x25519-sha256" {
		t.Fatalf("with a server that offers it, the key exchange is %q", got)
	}
	if relay.PostQuantumKex != "mlkem768x25519-sha256" {
		t.Fatalf("PostQuantumKex = %q", relay.PostQuantumKex)
	}

	// A server that has not been upgraded: it still works, and it shows.
	w.gate.Lock()
	w.gate.KeyExchanges = []string{"curve25519-sha256"}
	w.gate.Unlock()
	old := w.tunnel()
	defer old.Close()
	wantAnswer(t, ask(relay.NewSSH(old)))
	if got := old.KeyExchange(); got != "curve25519-sha256" {
		t.Fatalf("with an older server, the key exchange is %q", got)
	}
}

func TestTunnelComesBack(t *testing.T) {
	w := newWorld(t)
	tun := w.tunnel()
	defer tun.Close()
	rc := relay.NewSSH(tun)
	wantAnswer(t, ask(rc))

	// The server goes away...
	addr, key, relayAddr := w.gate.Addr, w.gate.Signer, w.gate.Relay
	w.gate.Close()
	if err := ask(rc); err == nil || relay.Status(err) != 0 {
		t.Fatalf("request without a server: %v", err)
	}
	// ...and comes back: the next request simply works again.
	gate, err := gatetest.Start(addr, relayAddr, key)
	if err != nil {
		t.Skipf("could not listen on %s again: %v", addr, err)
	}
	defer gate.Close()
	wantAnswer(t, ask(rc))
	if gate.Logins.Load() != 1 {
		t.Fatal("the client did not reconnect")
	}
}

func TestTunnelSaysWhatIsWrong(t *testing.T) {
	w := newWorld(t)
	tun := w.tunnel()
	defer tun.Close()
	rc := relay.NewSSH(tun)

	var ge *relay.GateError
	t.Run("the relay behind the entrance is down", func(t *testing.T) {
		w.gate.Lock()
		up := w.gate.Relay
		w.gate.Relay = ""
		w.gate.Unlock()
		err := ask(rc)
		if !errors.As(err, &ge) || !strings.Contains(ge.Reason, "not running") {
			t.Fatalf("got %v", err)
		}
		w.gate.Lock()
		w.gate.Relay = up
		w.gate.Unlock()
		wantAnswer(t, ask(rc)) // no reconnect needed, and none made
		if n := w.gate.Logins.Load(); n != 1 {
			t.Fatalf("%d SSH connections, want 1", n)
		}
	})

	t.Run("the server has no entrance for DMs", func(t *testing.T) {
		w.gate.Lock()
		w.gate.Closed = true
		w.gate.Unlock()
		tun.Close()
		err := ask(rc)
		if !errors.As(err, &ge) || !strings.Contains(ge.Reason, "no entrance for DMs") {
			t.Fatalf("got %v", err)
		}
		w.gate.Lock()
		w.gate.Closed = false
		w.gate.Unlock()
		wantAnswer(t, ask(rc))
	})
}

func TestHostKeyIsRemembered(t *testing.T) {
	w := newWorld(t)
	tun := w.tunnel()
	rc := relay.NewSSH(tun)
	wantAnswer(t, ask(rc)) // first use: trusted and remembered
	pin, err := os.ReadFile(tun.PinFile)
	if err != nil || !strings.HasPrefix(string(pin), w.gate.Addr+" ssh-ed25519 ") {
		t.Fatalf("pin file: %q, %v", pin, err)
	}
	if st, _ := os.Stat(tun.PinFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("pin file mode %v", st.Mode().Perm())
	}
	tun.Close()

	// Someone else answers at that address.
	addr, relayAddr := w.gate.Addr, w.gate.Relay
	w.gate.Close()
	other, err := gatetest.Start(addr, relayAddr, nil)
	if err != nil {
		t.Skipf("could not listen on %s again: %v", addr, err)
	}
	defer other.Close()
	for _, c := range []*relay.Client{rc, relay.NewSSH(w.tunnel())} { // this process, and the next
		err = ask(c)
		var hk *relay.HostKeyError
		if !errors.As(err, &hk) || hk.Record != tun.PinFile || !strings.Contains(hk.Got, "SHA256:") {
			t.Fatalf("a different host key was accepted: %v", err)
		}
	}
	if other.Logins.Load() != 0 {
		t.Fatal("the client went on with a server it should not trust")
	}
	// Nothing was overwritten.
	if now, _ := os.ReadFile(tun.PinFile); string(now) != string(pin) {
		t.Fatal("the pinned key changed")
	}
}

func TestKnownHostsIsHonoured(t *testing.T) {
	w := newWorld(t)
	kh := filepath.Join(w.dir, "known_hosts")
	wrong, _ := gatetest.NewHostKey()
	write := func(key ssh.PublicKey) {
		line := knownhosts.Line([]string{w.gate.Addr}, key)
		if err := os.WriteFile(kh, []byte("# the user's own file\n"+line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The user's SSH knows this server under another key: no first-use trust.
	write(wrong.PublicKey())
	tun := w.tunnel()
	tun.KnownHosts = []string{filepath.Join(w.dir, "missing"), kh}
	err := ask(relay.NewSSH(tun))
	var hk *relay.HostKeyError
	if !errors.As(err, &hk) || hk.Record != kh {
		t.Fatalf("known_hosts says otherwise, yet: %v", err)
	}
	if _, err := os.Stat(tun.PinFile); err == nil {
		t.Fatal("a key that known_hosts contradicts was pinned")
	}

	// With the right key there: accepted, and pinned for next time.
	write(w.gate.Signer.PublicKey())
	before, _ := os.ReadFile(kh)
	tun = w.tunnel()
	tun.KnownHosts = []string{kh}
	defer tun.Close()
	wantAnswer(t, ask(relay.NewSSH(tun)))
	if _, err := os.Stat(tun.PinFile); err != nil {
		t.Fatal("not pinned")
	}
	if after, _ := os.ReadFile(kh); string(after) != string(before) {
		t.Fatal("the user's known_hosts was written to")
	}
}

// A server that gains a second host key must not look like one whose key changed.
func TestPinnedKeyTypeIsAskedFor(t *testing.T) {
	w := newWorld(t)
	tun := w.tunnel()
	wantAnswer(t, ask(relay.NewSSH(tun)))
	tun.Close()
	pin, _ := os.ReadFile(tun.PinFile)
	// The pin survives other servers being remembered next to it.
	other := &relay.Tunnel{Addr: "127.0.0.1:1", PinFile: tun.PinFile}
	_ = ask(relay.NewSSH(other)) // nothing listens there; nothing is pinned
	if now, _ := os.ReadFile(tun.PinFile); string(now) != string(pin) {
		t.Fatalf("pin file changed: %q", now)
	}
	t2 := w.tunnel()
	defer t2.Close()
	wantAnswer(t, ask(relay.NewSSH(t2)))
}
