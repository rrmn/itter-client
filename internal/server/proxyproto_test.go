package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyProtocol(t *testing.T) {
	srv := New(NewMemStore(), Options{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s|%s", r.RemoteAddr, limitKey(srv.clientIP(r)))
	}))
	ts.Listener = ProxyListener(ts.Listener)
	ts.Start()
	defer ts.Close()
	addr := ts.Listener.Addr().String()

	// get sends first (a PROXY line, or whatever a client might send
	// instead) and then a request. It returns the body, or "" if the relay
	// hung up.
	get := func(first string) string {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(c, "%sGET / HTTP/1.1\r\nHost: relay\r\nConnection: close\r\n\r\n", first)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	for first, want := range map[string]string{
		"PROXY TCP4 203.0.113.7 127.0.0.1 50123 8080\r\n": "203.0.113.7:50123|203.0.113.7",
		"PROXY TCP6 2001:db8::7 ::1 50123 8080\r\n":       "[2001:db8::7]:50123|2001:db8::/64",
	} {
		if got := get(first); got != want {
			t.Errorf("%q: the relay saw %q, want %q", first, got, want)
		}
	}
	if got := get("PROXY UNKNOWN\r\n"); !strings.HasPrefix(got, "127.0.0.1:") {
		t.Errorf("PROXY UNKNOWN: the relay saw %q, want the proxy's own address", got)
	}

	// Whatever does not start with a proper PROXY line gets no answer at all:
	// in this mode nothing but itter's SSH app should be talking to the relay.
	for _, first := range []string{
		"", // a plain HTTP client
		"PROXY TCP4 203.0.113.7 127.0.0.1 50123\r\n",      // too short
		"PROXY TCP4 2001:db8::7 ::1 50123 8080\r\n",       // wrong family
		"PROXY TCP4 somewhere 127.0.0.1 50123 8080\r\n",   // not an address
		"PROXY TCP4 203.0.113.7 127.0.0.1 99999 8080\r\n", // not a port
		"PROXY UDP4 203.0.113.7 127.0.0.1 50123 8080\r\n", // not a protocol we know
		"PROXY TCP4 203.0.113.7 127.0.0.1 50123 8080\n",   // not the line ending
		"PROXY TCP4 " + strings.Repeat("1", 200) + "\r\n", // longer than any real one
	} {
		if got := get(first); got != "" {
			t.Errorf("%q was answered: %q", first, got)
		}
	}

	// A connection that says nothing must not hold up the others.
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	done := make(chan string, 1)
	go func() { done <- get("PROXY TCP4 198.51.100.9 127.0.0.1 4000 8080\r\n") }()
	select {
	case got := <-done:
		if got != "198.51.100.9:4000|198.51.100.9" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a silent connection blocked the relay")
	}
}

func TestParseProxyLine(t *testing.T) {
	self := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	for line, want := range map[string]string{
		"PROXY TCP4 192.0.2.1 127.0.0.1 1 2\r\n":   "192.0.2.1:1",
		"PROXY TCP6 ::1 ::1 65535 2\r\n":           "[::1]:65535",
		"PROXY UNKNOWN\r\n":                        "127.0.0.1:9",
		"PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n":    "127.0.0.1:9",
		"PROXY TCP4 192.0.2.1 127.0.0.1 1 2 3\r\n": "",
		"PROXY  TCP4 192.0.2.1 127.0.0.1 1 2\r\n":  "",
		"proxy TCP4 192.0.2.1 127.0.0.1 1 2\r\n":   "",
		"PROXY TCP4 192.0.2.1 127.0.0.1 -1 2\r\n":  "",
		"PROXY TCP4 ::ffff:192.0.2.1 ::1 1 2\r\n":  "192.0.2.1:1",
		"GET / HTTP/1.1\r\n":                       "",
		"\r\n":                                     "",
	} {
		got, err := parseProxyLine(line, self)
		switch {
		case want == "" && err == nil:
			t.Errorf("%q accepted as %v", line, got)
		case want != "" && (err != nil || got.String() != want):
			t.Errorf("%q = %v, %v; want %s", line, got, err, want)
		}
	}
}
