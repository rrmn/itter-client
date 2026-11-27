package server

import (
	"bufio"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// When the relay sits behind itter's SSH app, every connection reaches it
// from that app, on the same machine. So that rate limits still count real
// clients, the app starts each connection with one line of the PROXY
// protocol (version 1, the human-readable one):
//
//	PROXY TCP4 <client address> <proxy address> <client port> <proxy port>\r\n
//
// With Options.ProxyProtocol the relay requires that line and takes the
// client's address from it. Whoever can open a connection can then claim any
// address, so in this mode the relay must be reachable by the app only
// (listen on 127.0.0.1).

const (
	proxyHeaderMax     = 107 // longest version 1 line, as the specification says
	proxyHeaderTimeout = 5 * time.Second
)

// proxyListener hands out connections once their PROXY line has been read.
// Reading happens off the accept loop, so a client that sends nothing cannot
// hold up the others.
type proxyListener struct {
	net.Listener
	ready chan net.Conn
	done  chan struct{}
	once  sync.Once
	err   error
}

func newProxyListener(l net.Listener) *proxyListener {
	p := &proxyListener{Listener: l, ready: make(chan net.Conn), done: make(chan struct{})}
	go p.loop()
	return p
}

func (p *proxyListener) stop(err error) {
	p.once.Do(func() {
		p.err = err
		close(p.done)
	})
}

func (p *proxyListener) loop() {
	for {
		c, err := p.Listener.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				p.stop(err)
				return
			}
			time.Sleep(50 * time.Millisecond) // out of file descriptors and the like: try again
			continue
		}
		go func() {
			pc, err := readProxyHeader(c)
			if err != nil {
				c.Close()
				return
			}
			select {
			case p.ready <- pc:
			case <-p.done:
				c.Close()
			}
		}()
	}
}

func (p *proxyListener) Accept() (net.Conn, error) {
	select {
	case c := <-p.ready:
		return c, nil
	case <-p.done:
		if p.err != nil {
			return nil, p.err
		}
		return nil, net.ErrClosed
	}
}

func (p *proxyListener) Close() error {
	p.stop(net.ErrClosed)
	return p.Listener.Close()
}

// proxyConn is a connection whose client address came from its PROXY line.
type proxyConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (c *proxyConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *proxyConn) RemoteAddr() net.Addr       { return c.remote }

func readProxyHeader(c net.Conn) (net.Conn, error) {
	_ = c.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
	r := bufio.NewReaderSize(c, 4096)
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
		if len(line) >= proxyHeaderMax {
			return nil, errors.New("PROXY line too long")
		}
	}
	remote, err := parseProxyLine(string(line), c.RemoteAddr())
	if err != nil {
		return nil, err
	}
	_ = c.SetReadDeadline(time.Time{})
	return &proxyConn{Conn: c, r: r, remote: remote}, nil
}

// parseProxyLine returns the client address a PROXY line names. For "PROXY
// UNKNOWN" (the proxy cannot tell) it is the proxy's own address.
func parseProxyLine(line string, self net.Addr) (net.Addr, error) {
	if !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("malformed PROXY line")
	}
	f := strings.Split(strings.TrimSuffix(line, "\r\n"), " ")
	if len(f) < 2 || f[0] != "PROXY" {
		return nil, errors.New("not a PROXY line")
	}
	switch f[1] {
	case "UNKNOWN":
		return self, nil
	case "TCP4", "TCP6":
	default:
		return nil, errors.New("unsupported PROXY protocol")
	}
	if len(f) != 6 {
		return nil, errors.New("malformed PROXY line")
	}
	ip := net.ParseIP(f[2])
	port, err := strconv.ParseUint(f[4], 10, 16)
	if ip == nil || err != nil || (f[1] == "TCP4") != (ip.To4() != nil) {
		return nil, errors.New("malformed PROXY line")
	}
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}
