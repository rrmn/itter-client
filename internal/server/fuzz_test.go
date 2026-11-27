package server

import (
	"encoding/base64"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/rrmn/itter-client/internal/api"
)

// FuzzSessionHeaders: whatever stands in the headers that authenticate a
// request, the relay refuses it without falling over. (Nothing the fuzzer
// can make up is a MAC under a key it does not have.)
func FuzzSessionHeaders(f *testing.F) {
	mem := NewMemStore()
	mem.AddUser("alice")
	srv := New(mem, Options{TokenKey: make([]byte, 32)})
	good := ticketFor(&principal{user: User{ID: "mem-alice", Name: "alice"}, idID: "id", dev: "dev"}, time.Now().Add(time.Hour).Unix(), "sid")
	now := strconv.FormatInt(time.Now().Unix(), 10)
	f.Add(good, now, "00000000000000000000000000000000", base64.StdEncoding.EncodeToString(make([]byte, 32)), "/v1/inbox/alice", []byte(nil))
	f.Add("", "", "", "", "/", []byte("x"))
	f.Add("!!!", "soon", "zz", "@@", "/v1/keys/alice?x=1", []byte("{}"))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte("a\nb\nc\nd\n9999999999999999999999\nf")), now, "0123456789abcdef0123456789abcdef", "AAAA", "/v1/inbox/alice", []byte(nil))
	f.Fuzz(func(t *testing.T, ticket, ts, nonce, mac, uri string, body []byte) {
		req := httptest.NewRequest("GET", "/v1/inbox/alice", nil)
		req.URL.Path, req.URL.RawQuery = uri, ""
		req.Header.Set(api.SessionHeader, ticket)
		req.Header.Set(api.TimeHeader, ts)
		req.Header.Set(api.NonceHeader, nonce)
		req.Header.Set(api.AuthHeader, mac)
		if p, aerr := srv.checkSession(req, body); aerr == nil || p != nil {
			t.Fatalf("a made-up request was let in as %+v", p)
		}
	})
}
