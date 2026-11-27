package relay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"itter-cli/internal/api"
)

// The relay can be reached through itter's own SSH port, so nobody needs a
// second address. The client connects as the SSH user GateUser. That user
// needs no login: the relay authenticates every single request itself, with
// keys that never leave the device, exactly as it does over https. The client
// then asks for a channel to GateHost:GatePort, which is not a real address:
// itter's SSH app maps it to the relay running next to it. Over that channel
// the client speaks the same HTTP as always.
//
// The SSH connection is only a pipe. Nothing in the DM protocol depends on it
// being secure; like TLS before it, it merely keeps passers-by from watching
// or disturbing the traffic.
const (
	GateUser = "dm"
	GateHost = "itter-dm"
	GatePort = 1
)

// Tunnel is a connection to the relay through itter's SSH server. It is made
// when first needed and made again when it breaks.
type Tunnel struct {
	Addr string // itter's SSH server, host:port
	// PinFile is where the server's host key is remembered after the first
	// connection ("" = it is not remembered).
	PinFile string
	// KnownHosts are OpenSSH known_hosts files. If the server is listed in
	// one, its key has to match from the very first connection. They are
	// never written.
	KnownHosts []string

	mu  sync.Mutex
	cli *ssh.Client
	kex string // the key exchange the last handshake settled on
}

// PostQuantumKex is the hybrid key exchange (X25519 with ML-KEM-768) that
// the client prefers when the server offers it.
const PostQuantumKex = ssh.KeyExchangeMLKEM768X25519

// KeyExchange names the key exchange of the SSH connection, "" before there
// has been one. Nothing depends on it (see above); it is there to be shown.
func (t *Tunnel) KeyExchange() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.kex
}

// HostKeyError means itter's server showed another SSH host key than the one
// on record for it.
type HostKeyError struct {
	Addr   string
	Record string // the file that holds the key on record
	Got    string // fingerprint of the key that was shown
}

func (e *HostKeyError) Error() string {
	return fmt.Sprintf("the SSH host key of %s (%s) is not the one on record in %s", e.Addr, e.Got, e.Record)
}

// GateError means itter's server was reached but DMs cannot pass.
type GateError struct{ Reason string }

func (e *GateError) Error() string { return e.Reason }

// NewSSH returns a client that talks to the relay through t.
func NewSSH(t *Tunnel) *Client {
	mk := func(answer time.Duration) http.RoundTripper {
		if Transport != nil {
			return Transport
		}
		// No proxy on purpose: HTTP_PROXY and friends are about real web
		// addresses, and this is a private pipe.
		return &http.Transport{
			DialContext:           t.DialContext,
			ResponseHeaderTimeout: answer,
			// The entrance allows a handful of channels per connection. Staying
			// below that makes requests wait their turn here instead of being
			// turned away there.
			MaxConnsPerHost:     3,
			MaxIdleConnsPerHost: 3,
			IdleConnTimeout:     60 * time.Second,
		}
	}
	return &Client{
		Tunnel: t,
		Base:   "http://" + GateHost,
		Name:   "itter (ssh " + t.Addr + ")",
		HC:     &http.Client{Timeout: overall, Transport: mk(20 * time.Second)},
		Long:   &http.Client{Timeout: overall + api.MaxWait*time.Second, Transport: mk((api.MaxWait + 15) * time.Second)},
	}
}

// DialContext opens one more channel to the relay. The arguments after ctx
// are ignored: there is only one place this pipe leads to.
func (t *Tunnel) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	dest := net.JoinHostPort(GateHost, strconv.Itoa(GatePort))
	for attempt := 0; ; attempt++ {
		cli, fresh, err := t.client(ctx)
		if err != nil {
			return nil, err
		}
		ch, err := cli.DialContext(ctx, "tcp", dest)
		if err == nil {
			return ch, nil
		}
		var refused *ssh.OpenChannelError
		if errors.As(err, &refused) {
			// The server answered, and said no. Reconnecting changes nothing.
			if refused.Reason == ssh.ConnectionFailed {
				return nil, &GateError{"itter's DM relay is not running right now"}
			}
			return nil, &GateError{"this itter server does not let DMs through (" + strings.TrimSpace(refused.Message) + ")"}
		}
		t.drop(cli)
		if fresh || attempt > 0 || ctx.Err() != nil {
			return nil, err
		}
		// The connection had died since it was last used: once more, on a new one.
	}
}

// Close ends the connection. The next request makes a new one.
func (t *Tunnel) Close() {
	t.mu.Lock()
	cli := t.cli
	t.cli = nil
	t.mu.Unlock()
	if cli != nil {
		cli.Close()
	}
}

func (t *Tunnel) drop(cli *ssh.Client) {
	t.mu.Lock()
	if t.cli == cli {
		t.cli = nil
	}
	t.mu.Unlock()
	cli.Close()
}

// client returns the SSH connection, making it if there is none. fresh
// reports that it was made just now.
func (t *Tunnel) client(ctx context.Context) (cli *ssh.Client, fresh bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cli != nil {
		return t.cli, false, nil
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return nil, false, err
	}
	var hostErr error
	cfg := &ssh.ClientConfig{
		User:              GateUser,
		HostKeyCallback:   t.checkHostKey(&hostErr),
		HostKeyAlgorithms: t.pinnedAlgorithms(),
		ClientVersion:     "SSH-2.0-itter-dm",
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second)) // for the handshake
	cc, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	if err != nil {
		conn.Close()
		switch {
		case hostErr != nil:
			return nil, false, hostErr
		case strings.Contains(err.Error(), "unable to authenticate"):
			return nil, false, &GateError{"this itter server has no entrance for DMs (yet)"}
		}
		return nil, false, err
	}
	_ = conn.SetDeadline(time.Time{})
	if am, ok := cc.(ssh.AlgorithmsConnMetadata); ok {
		t.kex = am.Algorithms().KeyExchange
	}
	cli = ssh.NewClient(cc, chans, reqs)
	t.cli = cli
	go func() {
		_ = cli.Wait() // until the connection ends, for whatever reason
		t.drop(cli)
	}()
	return cli, true, nil
}

// --- the server's host key ---

func fingerprint(k ssh.PublicKey) string { return k.Type() + " " + ssh.FingerprintSHA256(k) }

// checkHostKey returns the host key check for one handshake. What it finds
// wrong is also stored in *report, because the SSH library wraps errors in a
// way that hides their type.
func (t *Tunnel) checkHostKey(report *error) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fail := func(record string) error {
			*report = &HostKeyError{Addr: t.Addr, Record: record, Got: fingerprint(key)}
			return *report
		}
		// 1. The key this device saw before.
		if pinned := t.pinned(); pinned != nil {
			if bytes.Equal(pinned.Marshal(), key.Marshal()) {
				return nil
			}
			return fail(t.PinFile)
		}
		// 2. Never been here: does the user's own SSH know the server?
		for _, file := range t.KnownHosts {
			if _, err := os.Stat(file); err != nil {
				continue
			}
			check, err := knownhosts.New(file)
			if err != nil {
				continue // a file OpenSSH would complain about too; not ours to fix
			}
			err = check(hostname, remote, key)
			var ke *knownhosts.KeyError
			switch {
			case err == nil:
				t.pin(key)
				return nil
			case errors.As(err, &ke) && len(ke.Want) > 0:
				return fail(file)
			}
		}
		// 3. Trust on first use, like ssh itself, and remember.
		t.pin(key)
		return nil
	}
}

// pinned returns the host key on record for t.Addr, nil if there is none.
func (t *Tunnel) pinned() ssh.PublicKey {
	if t.PinFile == "" {
		return nil
	}
	f, err := os.Open(t.PinFile)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 16<<10), 64<<10)
	for sc.Scan() {
		addr, rest, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok || addr != t.Addr {
			continue
		}
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rest)); err == nil {
			return key
		}
	}
	return nil
}

func (t *Tunnel) pin(key ssh.PublicKey) {
	if t.PinFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(t.PinFile), 0o700); err != nil {
		return
	}
	var keep []string
	if old, err := os.ReadFile(t.PinFile); err == nil {
		for _, line := range strings.Split(string(old), "\n") {
			if addr, _, ok := strings.Cut(strings.TrimSpace(line), " "); ok && addr != t.Addr {
				keep = append(keep, strings.TrimSpace(line))
			}
		}
	}
	keep = append(keep, t.Addr+" "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	tmp := t.PinFile + ".tmp"
	if os.WriteFile(tmp, []byte(strings.Join(keep, "\n")+"\n"), 0o600) == nil {
		_ = os.Rename(tmp, t.PinFile)
	}
}

// pinnedAlgorithms makes the server show the same kind of host key as the
// one on record, so that a server which gains a second key does not look
// like one whose key changed.
func (t *Tunnel) pinnedAlgorithms() []string {
	key := t.pinned()
	if key == nil {
		return nil
	}
	switch key.Type() {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	default:
		return []string{key.Type()}
	}
}
