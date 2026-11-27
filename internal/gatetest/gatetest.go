// Package gatetest is a stand-in, for tests, for the entrance that itter's
// SSH app offers the DM client (itter/ssh/dm_gate.py in the itter app): an
// SSH user that needs no login, one kind of channel, piped to the relay
// behind a PROXY protocol line.
package gatetest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"itter-cli/internal/relay"
)

// Gate is a running stand-in. Its exported fields may be changed while it
// runs, under Lock.
type Gate struct {
	sync.Mutex
	// Relay is where channels are piped to ("" = the relay is down).
	Relay string
	// Closed turns the entrance off: user "dm" is then asked to log in like
	// anybody else, which it cannot.
	Closed bool
	// KeyExchanges limits what the server offers to new connections (nil =
	// everything, the post-quantum hybrid first). An SSH server that has not
	// been upgraded looks like []string{"curve25519-sha256"}.
	KeyExchanges []string

	Addr   string     // where the gate listens
	Signer ssh.Signer // its host key

	Logins   atomic.Int64 // SSH connections that got in
	Channels atomic.Int64 // channels piped to the relay

	l     net.Listener
	conns map[net.Conn]bool
}

// NewHostKey makes a host key for a gate.
func NewHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// Start runs a gate on addr ("127.0.0.1:0" for any free port) with the given
// host key (nil: a new one).
func Start(addr, relayAddr string, hostKey ssh.Signer) (*Gate, error) {
	if hostKey == nil {
		var err error
		if hostKey, err = NewHostKey(); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	g := &Gate{Relay: relayAddr, Addr: l.Addr().String(), Signer: hostKey, l: l, conns: map[net.Conn]bool{}}
	go g.accept()
	return g, nil
}

// Close stops the gate and drops every connection, like a server going away.
func (g *Gate) Close() {
	g.l.Close()
	g.Lock()
	for c := range g.conns {
		c.Close()
	}
	g.conns = map[net.Conn]bool{}
	g.Unlock()
}

func (g *Gate) accept() {
	for {
		c, err := g.l.Accept()
		if err != nil {
			return
		}
		g.Lock()
		g.conns[c] = true
		g.Unlock()
		go g.serve(c)
	}
}

func (g *Gate) serve(c net.Conn) {
	defer func() {
		c.Close()
		g.Lock()
		delete(g.conns, c)
		g.Unlock()
	}()
	cfg := &ssh.ServerConfig{
		NoClientAuth: true,
		NoClientAuthCallback: func(m ssh.ConnMetadata) (*ssh.Permissions, error) {
			g.Lock()
			defer g.Unlock()
			if m.User() != relay.GateUser || g.Closed {
				return nil, errors.New("login required")
			}
			return nil, nil
		},
		// Everybody else has to log in with a key; nobody here has one.
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("unknown key")
		},
	}
	g.Lock()
	cfg.KeyExchanges = g.KeyExchanges
	g.Unlock()
	cfg.AddHostKey(g.Signer)
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	g.Logins.Add(1)
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		g.channel(sc, nc)
	}
}

func (g *Gate) channel(sc *ssh.ServerConn, nc ssh.NewChannel) {
	if nc.ChannelType() != "direct-tcpip" {
		_ = nc.Reject(ssh.ConnectionFailed, "Session refused")
		return
	}
	var req struct {
		DestHost string
		DestPort uint32
		OrigHost string
		OrigPort uint32
	}
	if ssh.Unmarshal(nc.ExtraData(), &req) != nil || req.DestHost != relay.GateHost || req.DestPort != relay.GatePort {
		_ = nc.Reject(ssh.ConnectionFailed, "Connection refused")
		return
	}
	g.Lock()
	relayAddr := g.Relay
	g.Unlock()
	var up net.Conn
	var err error = errors.New("down")
	if relayAddr != "" {
		up, err = net.DialTimeout("tcp", relayAddr, 5*time.Second)
	}
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "DM relay unavailable")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		up.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	g.Channels.Add(1)
	client, _ := sc.RemoteAddr().(*net.TCPAddr)
	_, relayPort, _ := net.SplitHostPort(relayAddr)
	if client != nil && client.IP.To4() != nil {
		fmt.Fprintf(up, "PROXY TCP4 %s 127.0.0.1 %d %s\r\n", client.IP, client.Port, relayPort)
	} else if client != nil {
		fmt.Fprintf(up, "PROXY TCP6 %s ::1 %d %s\r\n", client.IP, client.Port, relayPort)
	} else {
		fmt.Fprint(up, "PROXY UNKNOWN\r\n")
	}
	go func() {
		_, _ = io.Copy(up, ch)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		_, _ = io.Copy(ch, up)
		ch.Close()
		up.Close()
	}()
}
