// Package server is the itter DM relay. It stores public keys and opaque
// ciphertexts; it never sees plaintext or private keys.
package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rrmn/itter-client/internal/api"
	"github.com/rrmn/itter-client/internal/pqc"
)

const (
	authWindow    = 120 * time.Second
	releaseSkew   = 10 * time.Minute
	sessionTTL    = 30 * 24 * time.Hour
	maxOTPKBatch  = 100
	maxOTPKStored = 300
	inboxPerPair  = 500     // messages one sender may have waiting for one recipient
	pageSize      = 50      // messages per fetch, at most...
	pageBytes     = 1 << 20 // ...and about this much, so a page also fits through a slow link
	maxAck        = 500
	claimsPerDay  = 10 // times per day one account may take one-time prekeys from another
	maxLinks      = 3  // link requests that may wait for one account
	waitRecheck   = 10 * time.Second
	limitIP       = 240 // unauthenticated requests per minute and address
	limitSend     = 120 // messages per minute and sender
	limitAuthFail = 30  // failed authentications per minute and address
	limitSessions = 30  // sessions one device may open per hour
)

var (
	nonceRE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	deviceRE = nonceRE // device and link IDs look the same: 16 bytes in hex
)

// Options configures a relay.
type Options struct {
	// TokenKey is what the keys of sessions are made from. Empty means a
	// random key: sessions then die with the process (clients open new ones),
	// and several relay instances cannot share them.
	TokenKey []byte
	// ClientIPHeader names the header a trusted reverse proxy sets to the
	// client address (e.g. "Fly-Client-IP"). Without it the TCP peer address
	// is used, which behind a proxy is the proxy for everyone.
	ClientIPHeader string
	// ProxyProtocol makes the relay expect a PROXY protocol line at the start
	// of every connection and take the client's address from it. That is how
	// itter's SSH app passes clients on; see proxyproto.go.
	ProxyProtocol bool
}

type Server struct {
	store Store
	opt   Options
	now   func() time.Time

	mu     sync.Mutex
	limits map[string]*counter
	nonces map[string]time.Time
	// noncesSwept is when old entries were last thrown out of nonces.
	noncesSwept time.Time
	waiters     map[string]map[chan struct{}]struct{}
}

type counter struct {
	n     int
	reset time.Time
}

func New(store Store, opt Options) *Server {
	if len(opt.TokenKey) < 32 {
		opt.TokenKey = make([]byte, 32)
		if _, err := rand.Read(opt.TokenKey); err != nil {
			panic(err)
		}
	}
	return &Server{store: store, opt: opt, now: time.Now, limits: map[string]*counter{},
		nonces: map[string]time.Time{}, waiters: map[string]map[chan struct{}]struct{}{}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/register", s.handleRegister)
	mux.HandleFunc("DELETE /v1/register", s.handleRelease)
	mux.HandleFunc("POST /v1/session/{user}", s.handleSession)
	mux.HandleFunc("PUT /v1/keys/{user}", s.handleUploadKeys)
	mux.HandleFunc("GET /v1/keys/{user}", s.handleGetBundle)
	mux.HandleFunc("POST /v1/keys/{user}/claim", s.handleClaimBundle)
	mux.HandleFunc("GET /v1/keys/{user}/count", s.handleKeyCount)
	mux.HandleFunc("POST /v1/msg/{user}", s.handlePostMsg)
	mux.HandleFunc("GET /v1/inbox/{user}", s.handleInbox)
	mux.HandleFunc("GET /v1/inbox/{user}/from/{sender}", s.handleInboxFrom)
	mux.HandleFunc("POST /v1/inbox/{user}/ack", s.handleAck)
	mux.HandleFunc("GET /v1/devices/{user}", s.handleDevices)
	mux.HandleFunc("PUT /v1/devices/{user}", s.handleSetDevices)
	mux.HandleFunc("DELETE /v1/devices/{user}", s.handleRetireDevice)
	mux.HandleFunc("POST /v1/link/{user}", s.handleLinkRequest)
	mux.HandleFunc("GET /v1/link/{user}/{id}", s.handleLinkGet)
	mux.HandleFunc("PUT /v1/link/{user}/{id}", s.handleLinkAnswer)
	mux.HandleFunc("GET /v1/link/{user}/{id}/result", s.handleLinkResult)
	mux.HandleFunc("GET /v1/ignore/{user}", s.handleIgnoreList)
	mux.HandleFunc("PUT /v1/ignore/{user}/{peer}", s.handleIgnoreSet)
	mux.HandleFunc("DELETE /v1/ignore/{user}/{peer}", s.handleIgnoreSet)
	return mux
}

// Run serves the relay on addr.
func Run(addr string, store Store, opt Options) error {
	log.Printf("itter-relay listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           New(store, opt).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      (api.MaxWait + 120) * time.Second, // long-polls hold a response open
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if opt.ProxyProtocol {
		l = newProxyListener(l)
	}
	return srv.Serve(l)
}

// ProxyListener wraps l so that every connection must start with a PROXY
// protocol line (for tests and for embedding the relay).
func ProxyListener(l net.Listener) net.Listener { return newProxyListener(l) }

// ReleaseIdentity removes a user's DM identity. It is the operator's tool for
// someone who lost both their device and their recovery code.
func ReleaseIdentity(store Store, username string) error {
	u, err := store.User(username)
	if err != nil {
		return err
	}
	return store.DeleteIdentity(u.ID)
}

// --- helpers ---

func fail(w http.ResponseWriter, status int, msg string) { http.Error(w, msg, status) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, "request too large")
		return nil, false
	}
	return b, true
}

func (s *Server) clientIP(r *http.Request) string {
	if h := s.opt.ClientIPHeader; h != "" {
		if v := strings.TrimSpace(strings.Split(r.Header.Get(h), ",")[0]); v != "" {
			return v
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// limitKey is the rate-limit bucket of an address: IPv6 hosts own a whole
// /64, so they are counted by network, not by address.
func limitKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// allow counts one event against a per-minute (or per-window) limit.
func (s *Server) allow(key string, limit int, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.limits) > 200000 {
		for k, c := range s.limits {
			if now.After(c.reset) {
				delete(s.limits, k)
			}
		}
	}
	c := s.limits[key]
	if c == nil || now.After(c.reset) {
		s.limits[key] = &counter{n: 1, reset: now.Add(window)}
		return true
	}
	c.n++
	return c.n <= limit
}

func (s *Server) allowIP(w http.ResponseWriter, r *http.Request) bool {
	if !s.allow("ip:"+limitKey(s.clientIP(r)), limitIP, time.Minute) {
		fail(w, http.StatusTooManyRequests, "rate limited")
		return false
	}
	return true
}

// --- authentication ---

type principal struct {
	user User
	idID string // the account identity's ID
	dev  string // the calling device's ID; the first device's is idID
}

func (p *principal) primary() bool { return p.dev == p.idID }

type authError struct {
	msg  string
	skew bool
	// down: not the caller's fault. The store could not be asked, so nothing
	// is known about the caller. It must not be told that it is unknown: a
	// client takes that to mean its device is gone for good.
	down bool
}

var (
	errAuth     = &authError{msg: "authentication failed"}
	errSkew     = &authError{msg: api.ErrClockSkew, skew: true}
	errIdentity = &authError{msg: api.ErrUnknownIdentity}
	errSession  = &authError{msg: api.ErrSessionGone}
	errStore    = &authError{msg: "internal error", down: true}
)

// A session ticket names who a session belongs to and until when. It is not
// a secret and proves nothing: what counts is the session key, which only
// the relay (from TokenKey) and the device that opened the session have.
func ticketFor(p *principal, exp int64, sid string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(
		[]string{p.user.ID, p.user.Name, p.idID, p.dev, strconv.FormatInt(exp, 10), sid}, "\n")))
}

func (s *Server) sessionKey(ticket string) []byte {
	mac := hmac.New(sha512.New512_256, s.opt.TokenKey)
	mac.Write([]byte("itter/v2/relay-session-key\n" + ticket))
	return mac.Sum(nil)
}

// checkSession identifies the caller of a request by its session: the MAC
// made with the session key, its freshness, and that its nonce was never
// used before. A request that was read off the wire is good for nothing but
// itself, once.
func (s *Server) checkSession(r *http.Request, body []byte) (*principal, *authError) {
	ticket := r.Header.Get(api.SessionHeader)
	raw, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil || len(raw) == 0 || len(raw) > 512 {
		return nil, errAuth
	}
	f := strings.Split(string(raw), "\n")
	if len(f) != 6 {
		return nil, errAuth
	}
	exp, err := strconv.ParseInt(f[4], 10, 64)
	if err != nil {
		return nil, errAuth
	}
	ts, err := strconv.ParseInt(r.Header.Get(api.TimeHeader), 10, 64)
	if err != nil {
		return nil, errAuth
	}
	nonce := r.Header.Get(api.NonceHeader)
	if !nonceRE.MatchString(nonce) {
		return nil, errAuth
	}
	got, err := base64.StdEncoding.DecodeString(r.Header.Get(api.AuthHeader))
	if err != nil {
		return nil, errAuth
	}
	bh := sha512.Sum512(body)
	want := api.RequestMAC(s.sessionKey(ticket), r.Method, r.URL.RequestURI(), ts, nonce, bh[:])
	if !hmac.Equal(got, want) {
		// Not made with the key of this ticket. Most likely the relay was
		// restarted with another TokenKey: the client opens a new session.
		return nil, errSession
	}
	// From here on the ticket is known to be one of ours.
	now := s.now()
	if now.Unix() > exp {
		return nil, errSession
	}
	if d := now.Sub(time.Unix(ts, 0)); d > authWindow || d < -authWindow {
		return nil, errSkew
	}
	if !s.useNonce(f[5] + "/" + nonce) {
		return nil, errAuth
	}
	// A session ends with the identity it was opened for, and with the device.
	cur, devs, err := s.store.DeviceIDs(f[0])
	if err != nil {
		log.Printf("session of %s: %v", f[1], err)
		return nil, errStore
	}
	if cur == "" || cur != f[2] || !slices.Contains(devs, f[3]) {
		return nil, errIdentity
	}
	return &principal{user: User{ID: f[0], Name: f[1]}, idID: f[2], dev: f[3]}, nil
}

// deviceKey returns the key of one of the account's devices, nil if the
// account has no such device (any more).
func (s *Server) deviceKey(rec *IdentityRecord, userID, dev string) ([]byte, error) {
	if dev == rec.ID {
		return rec.Identity, nil
	}
	devs, err := s.store.Devices(userID)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		if d.ID == dev {
			return d.Key, nil
		}
	}
	return nil, nil
}

func (s *Server) useNonce(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Not on every request once the map is big: under load that would be a
	// walk through all of it each time.
	if len(s.nonces) > 50000 && now.Sub(s.noncesSwept) > 30*time.Second {
		s.noncesSwept = now
		for k, t := range s.nonces {
			if now.Sub(t) > 2*authWindow {
				delete(s.nonces, k)
			}
		}
	}
	if _, seen := s.nonces[key]; seen {
		return false
	}
	s.nonces[key] = now
	return true
}

// authBlocked refuses addresses that keep failing to authenticate. If it
// returns true it has already written the response.
func (s *Server) authBlocked(w http.ResponseWriter, r *http.Request) bool {
	ipKey := "authfail:" + limitKey(s.clientIP(r))
	s.mu.Lock()
	blocked := s.limits[ipKey] != nil && s.limits[ipKey].n > limitAuthFail && s.now().Before(s.limits[ipKey].reset)
	s.mu.Unlock()
	if blocked {
		fail(w, http.StatusTooManyRequests, "rate limited")
	}
	return blocked
}

// authFailed counts a failed authentication and writes the response.
func (s *Server) authFailed(w http.ResponseWriter, r *http.Request, aerr *authError) {
	if aerr.down {
		fail(w, http.StatusInternalServerError, aerr.msg)
		return
	}
	// A session the relay no longer has is not held against the address:
	// after a restart that is every client's first request, and people who
	// share an address would lock each other out. (There is nothing to guess
	// here either: a MAC is 256 bits.)
	if aerr != errSession {
		s.allow("authfail:"+limitKey(s.clientIP(r)), limitAuthFail, time.Minute)
	}
	if aerr.skew {
		w.Header().Set(api.TimeHeader, strconv.FormatInt(s.now().Unix(), 10))
	}
	fail(w, http.StatusUnauthorized, aerr.msg)
}

// authenticate identifies the caller by the session the request belongs to.
// On failure it has already written the response.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, body []byte) *principal {
	if s.authBlocked(w, r) {
		return nil
	}
	p, aerr := s.checkSession(r, body)
	if aerr != nil {
		s.authFailed(w, r, aerr)
		return nil
	}
	return p
}

// handleSession opens a session for a device. This is the one place where a
// device proves itself with its key: a full signature, the hash-based part
// included, over a request that carries one-time public keys. The relay
// answers with a key agreement only that device can complete, and with the
// session key locked under its result. Whoever listens learns a ticket, which
// is no secret, and nothing they could make a request with.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if !s.allowIP(w, r) || s.authBlocked(w, r) {
		return
	}
	body, ok := readBody(w, r, 256<<10)
	if !ok {
		return
	}
	name := r.PathValue("user")
	var req api.SessionReq
	if json.Unmarshal(body, &req) != nil || !api.ValidUsername(name) || !deviceRE.MatchString(req.Device) ||
		!nonceRE.MatchString(req.Nonce) || len(req.Offer) != pqc.SessionOfferSize() || len(req.Sig) != pqc.FullSigSize {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if d := s.now().Sub(time.Unix(req.TS, 0)); d > authWindow || d < -authWindow {
		s.authFailed(w, r, errSkew)
		return
	}
	u, err := s.store.User(name)
	if errors.Is(err, errNotFound) {
		s.authFailed(w, r, errIdentity) // no such account (any more)
		return
	}
	var rec *IdentityRecord
	var key []byte
	if err == nil {
		rec, err = s.store.Identity(u.ID)
	}
	if err == nil && rec != nil {
		key, err = s.deviceKey(rec, u.ID, req.Device)
	}
	if err != nil {
		log.Printf("session for %s: %v", name, err)
		s.authFailed(w, r, errStore)
		return
	}
	if rec == nil || key == nil {
		s.authFailed(w, r, errIdentity) // no identity, or not (no longer) one of the account's devices
		return
	}
	ik, err := pqc.DecodeIdentityKey(key)
	if err != nil || ik.VerifyFull(api.SessionPayload(name, req.Device, req.TS, req.Nonce, req.Offer), req.Sig, "relay-session") != nil {
		// Most likely a client whose identity was replaced on the relay.
		s.authFailed(w, r, errIdentity)
		return
	}
	if !s.useNonce("session/" + u.ID + "/" + req.Nonce) {
		s.authFailed(w, r, errAuth)
		return
	}
	if !s.allow("session:"+u.ID+"/"+req.Device, limitSessions, time.Hour) {
		fail(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	exp := s.now().Add(sessionTTL).Unix()
	ticket := ticketFor(&principal{user: u, idID: rec.ID, dev: req.Device}, exp, hex.EncodeToString(sid[:]))
	answer, secret, err := pqc.AnswerSession(req.Offer, []byte(ticket))
	if err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	box, err := pqc.WrapSessionKey(secret, []byte(ticket), s.sessionKey(ticket))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, api.SessionResp{Ticket: ticket, Answer: answer, Box: box, Expires: exp})
}

// identityOf fetches the caller's identity record for handlers that need
// what is in it. A store that cannot be asked is an error of ours, never
// "unknown identity": a client takes that to mean its device is gone for good.
func (s *Server) identityOf(w http.ResponseWriter, p *principal) *IdentityRecord {
	rec, err := s.store.Identity(p.user.ID)
	switch {
	case err != nil:
		log.Printf("identity of %s: %v", p.user.Name, err)
		fail(w, http.StatusInternalServerError, "internal error")
	case rec == nil:
		fail(w, http.StatusUnauthorized, api.ErrUnknownIdentity)
	default:
		return rec
	}
	return nil
}

// authenticateAs additionally requires the caller to be the user in the path.
func (s *Server) authenticateAs(w http.ResponseWriter, r *http.Request, body []byte) *principal {
	p := s.authenticate(w, r, body)
	if p == nil {
		return nil
	}
	if !strings.EqualFold(r.PathValue("user"), p.user.Name) {
		fail(w, http.StatusForbidden, "not your account")
		return nil
	}
	return p
}

// --- registration ---

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.allowIP(w, r) {
		return
	}
	body, ok := readBody(w, r, 1<<20)
	if !ok {
		return
	}
	var req api.RegReq
	if json.Unmarshal(body, &req) != nil || !api.ValidUsername(req.Username) || len(req.RecoveryKey) != pqc.RecoveryPublicSize {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	ik, err := pqc.DecodeIdentityKey(req.Identity)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid identity key")
		return
	}
	if d := s.now().Sub(time.Unix(req.TS, 0)); d > releaseSkew || d < -releaseSkew {
		w.Header().Set(api.TimeHeader, strconv.FormatInt(s.now().Unix(), 10))
		fail(w, http.StatusUnauthorized, api.ErrClockSkew) // stale: a replay, or a wrong clock
		return
	}
	payload := api.RegPayload(req.Username, req.Identity, req.RecoveryKey, req.TS)
	if ik.VerifyFull(payload, req.IDSig, "dm-binding") != nil {
		fail(w, http.StatusForbidden, "identity proof-of-possession failed")
		return
	}
	u, err := s.store.User(req.Username)
	if err != nil {
		fail(w, http.StatusNotFound, "user not found on itter")
		return
	}
	if !s.verifySSHBinding(u.ID, payload, req.SSHSigs) {
		fail(w, http.StatusForbidden, "no valid signature from a non-RSA SSH key on this itter account")
		return
	}

	// One identity per account, first writer wins. Replacing it takes the
	// old identity's consent (release) or the recovery code, so a stolen or
	// forged SSH key cannot hijack existing DMs.
	const taken = "this account already has a DM identity"
	rec := &IdentityRecord{Identity: req.Identity, ID: pqc.IdentityID(req.Identity), RecoveryKey: req.RecoveryKey}
	old, err := s.store.Identity(u.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if old == nil {
		created, err := s.store.CreateIdentity(u, rec)
		if err != nil {
			log.Printf("register %s: %v", u.Name, err)
			fail(w, http.StatusInternalServerError, "registration failed")
			return
		}
		if !created { // lost a race
			if old, err = s.store.Identity(u.ID); err != nil || old == nil {
				fail(w, http.StatusInternalServerError, "registration failed")
				return
			}
		}
	}
	if old != nil && !bytes.Equal(old.Identity, req.Identity) {
		fail(w, http.StatusConflict, taken)
		return
	}
	writeJSON(w, http.StatusCreated, api.RegResp{Username: u.Name})
}

func (s *Server) verifySSHBinding(userID string, payload []byte, sigs []api.SSHSig) bool {
	keys, err := s.store.SSHKeys(userID)
	if err != nil {
		return false
	}
	if len(sigs) > 32 {
		sigs = sigs[:32]
	}
	for _, line := range keys {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || !api.AllowedSSHKeyType(pk.Type()) {
			continue // RSA keys (and anything unknown) never count
		}
		for _, sg := range sigs {
			if !api.AllowedSSHSigFormat(sg.Format) {
				continue
			}
			if pk.Verify(payload, &ssh.Signature{Format: sg.Format, Blob: sg.Blob, Rest: sg.Rest}) == nil {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if !s.allowIP(w, r) {
		return
	}
	body, ok := readBody(w, r, 1<<20)
	if !ok {
		return
	}
	var req api.ReleaseReq
	if json.Unmarshal(body, &req) != nil || !api.ValidUsername(req.Username) {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := s.store.User(req.Username)
	if err != nil {
		fail(w, http.StatusNotFound, "user not found on itter")
		return
	}
	rec, err := s.store.Identity(u.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if rec == nil {
		w.WriteHeader(http.StatusNoContent) // nothing to release
		return
	}
	// Either way it is a signature over the account and the time: a request
	// that was recorded releases nothing once the window has passed.
	if d := s.now().Sub(time.Unix(req.TS, 0)); d > releaseSkew || d < -releaseSkew {
		w.Header().Set(api.TimeHeader, strconv.FormatInt(s.now().Unix(), 10))
		fail(w, http.StatusUnauthorized, api.ErrClockSkew)
		return
	}
	if len(req.RecoverySig) > 0 {
		// Made with the recovery code, which itself goes nowhere. It is
		// checked against the key of the identity that is registered now.
		if pqc.RecoveryVerify(rec.RecoveryKey, api.RecoverPayload(req.Username, req.TS), req.RecoverySig) != nil {
			fail(w, http.StatusForbidden, "wrong recovery code")
			return
		}
	} else {
		ik, err := pqc.DecodeIdentityKey(rec.Identity)
		if err != nil || ik.VerifyFull(api.ReleasePayload(req.Username, rec.Identity, req.TS), req.Sig, "dm-release") != nil {
			fail(w, http.StatusForbidden, "signature invalid")
			return
		}
	}
	if err := s.store.DeleteIdentity(u.ID); err != nil {
		log.Printf("release %s: %v", u.Name, err)
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- prekeys ---

func (s *Server) handleUploadKeys(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r, 8<<20)
	if !ok {
		return
	}
	p := s.authenticateAs(w, r, body)
	if p == nil {
		return
	}
	var up api.KeysUpload
	if json.Unmarshal(body, &up) != nil || up.SPK == nil || len(up.OTPKs) > maxOTPKBatch {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	rec := s.identityOf(w, p)
	if rec == nil {
		return
	}
	key, err := s.deviceKey(rec, p.user.ID, p.dev)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if key == nil {
		fail(w, http.StatusUnauthorized, api.ErrUnknownIdentity)
		return
	}
	// Check the signed prekey exactly as clients will: against the device's key.
	check := &pqc.PublicBundle{Username: p.user.Name, Identity: key, SPK: up.SPK, SPKSig: up.SPKSig}
	if _, err := check.Verify(); err != nil {
		fail(w, http.StatusForbidden, "signed prekey invalid")
		return
	}
	for _, k := range up.OTPKs {
		if !k.Valid() || k.ID == 0 {
			fail(w, http.StatusBadRequest, "bad one-time prekey")
			return
		}
	}
	if n, err := s.store.CountOTPKs(p.user.ID, p.dev); err == nil && n+len(up.OTPKs) > maxOTPKStored {
		up.OTPKs = nil // plenty in stock; still accept the signed prekey
	}
	if err := s.store.PutPreKeys(p.user.ID, p.dev, up.SPK, up.SPKSig, up.OTPKs); err != nil {
		log.Printf("upload keys %s: %v", p.user.Name, err)
		fail(w, http.StatusInternalServerError, "failed to store keys")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// directory assembles what the relay lists for an account: identity, signed
// device list and, for every device that has published prekeys, its bundle
// (without a one-time prekey).
func (s *Server) directory(w http.ResponseWriter, name string) (*api.Directory, User, bool) {
	if !api.ValidUsername(name) {
		fail(w, http.StatusBadRequest, "bad user")
		return nil, User{}, false
	}
	u, err := s.store.User(name)
	if err != nil {
		fail(w, http.StatusNotFound, "no such user")
		return nil, User{}, false
	}
	rec, err := s.store.Identity(u.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return nil, User{}, false
	}
	if rec == nil {
		fail(w, http.StatusGone, api.ErrNoIdentity)
		return nil, User{}, false
	}
	devs, err1 := s.store.Devices(u.ID)
	spks, err2 := s.store.SignedPreKeys(u.ID)
	if err1 != nil || err2 != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return nil, User{}, false
	}
	d := &api.Directory{Username: u.Name, Identity: rec.Identity}
	if len(rec.List) > 0 {
		var l pqc.DeviceList
		if json.Unmarshal(rec.List, &l) == nil {
			d.List = &l
		}
	}
	for _, dev := range devs {
		if k, ok := spks[dev.ID]; ok {
			d.Devices = append(d.Devices, &pqc.PublicBundle{Username: u.Name, Identity: dev.Key, SPK: k.Key, SPKSig: k.Sig})
		}
	}
	if len(d.Devices) == 0 {
		fail(w, http.StatusGone, api.ErrNoIdentity) // registered, setup not finished
		return nil, User{}, false
	}
	return d, u, true
}

// handleGetBundle serves the directory entry to anyone (enough to show a
// fingerprint). It never hands out one-time prekeys.
func (s *Server) handleGetBundle(w http.ResponseWriter, r *http.Request) {
	if !s.allowIP(w, r) {
		return
	}
	if d, _, ok := s.directory(w, r.PathValue("user")); ok {
		writeJSON(w, http.StatusOK, d)
	}
}

// handleClaimBundle also hands out one-time prekeys. Callers must be
// registered and get only a few per day and recipient, so nobody can drain
// another user's stock; someone the recipient ignores gets none.
func (s *Server) handleClaimBundle(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r, 1<<12)
	if !ok {
		return
	}
	p := s.authenticate(w, r, body)
	if p == nil {
		return
	}
	var req api.ClaimReq
	if len(body) > 0 && json.Unmarshal(body, &req) != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	d, u, ok := s.directory(w, r.PathValue("user"))
	if !ok {
		return
	}
	own := u.ID == p.user.ID
	ignored := false
	if !own {
		ignored, _ = s.store.Ignores(u.ID, p.user.ID)
	}
	if !ignored && (own || s.allow("claim:"+p.user.ID+">"+u.ID, claimsPerDay, 24*time.Hour)) {
		for _, b := range d.Devices {
			id := pqc.IdentityID(b.Identity)
			if (len(req.Devices) > 0 && !slices.Contains(req.Devices, id)) || (own && id == p.dev) {
				continue
			}
			if otpk, err := s.store.ClaimOTPK(u.ID, id); err == nil && otpk != nil {
				b.OTPK = otpk
			}
		}
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleKeyCount(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAs(w, r, nil)
	if p == nil {
		return
	}
	n, err := s.store.CountOTPKs(p.user.ID, p.dev)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, api.KeyCountResp{OTPKs: n})
}

// --- messages ---

func (s *Server) handlePostMsg(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r, api.MaxDevices*api.MaxMessageSize+1<<12)
	if !ok {
		return
	}
	p := s.authenticate(w, r, raw)
	if p == nil {
		return
	}
	if !s.allow("send:"+p.user.ID, limitSend, time.Minute) {
		fail(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	to := r.PathValue("user")
	var req api.SendReq
	if !api.ValidUsername(to) || json.Unmarshal(raw, &req) != nil || len(req.Msgs) == 0 || len(req.Msgs) > api.MaxDevices {
		fail(w, http.StatusBadRequest, "malformed message")
		return
	}
	msgs := make(map[string][]byte, len(req.Msgs))
	for dev, m := range req.Msgs {
		if len(m) > api.MaxMessageSize {
			fail(w, http.StatusRequestEntityTooLarge, "message too large")
			return
		}
		var wm pqc.WireMsg
		if !deviceRE.MatchString(dev) || json.Unmarshal(m, &wm) != nil ||
			(wm.Type != pqc.WireInitial && wm.Type != pqc.WireEnvelope) || len(wm.Payload) == 0 {
			fail(w, http.StatusBadRequest, "malformed message")
			return
		}
		if wm.From != p.user.Name || wm.Dev != p.dev {
			fail(w, http.StatusForbidden, "sender does not match the authenticated account")
			return
		}
		msgs[dev] = m
	}
	u, err := s.store.User(to)
	if err != nil {
		fail(w, http.StatusNotFound, "no such user")
		return
	}
	// Refuse what the recipient cannot decrypt, and what would miss one of
	// their devices, so the sender finds out now instead of the message
	// vanishing.
	cur, _, err := s.store.DeviceIDs(u.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if cur == "" {
		fail(w, http.StatusGone, api.ErrNoIdentity)
		return
	}
	if req.ToID != cur {
		fail(w, http.StatusConflict, api.ErrIdentityChanged)
		return
	}
	spks, err := s.store.SignedPreKeys(u.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	need := 0
	for dev := range spks {
		if u.ID == p.user.ID && dev == p.dev {
			continue // one's own other devices: everything but the sender
		}
		need++
		if _, ok := msgs[dev]; !ok {
			fail(w, http.StatusConflict, api.ErrDevicesChanged)
			return
		}
	}
	if need == 0 {
		fail(w, http.StatusGone, api.ErrNoIdentity)
		return
	}
	if need != len(msgs) {
		fail(w, http.StatusConflict, api.ErrDevicesChanged)
		return
	}
	if u.ID != p.user.ID {
		// What a user ignores on itter does not reach them here either. The
		// sender is not told, like on itter.
		if ignored, _ := s.store.Ignores(u.ID, p.user.ID); ignored {
			w.WriteHeader(http.StatusCreated)
			return
		}
	}
	stored, err := s.store.PutMessages(u.ID, p.user.Name, msgs, inboxPerPair)
	if err != nil {
		log.Printf("post msg: %v", err)
		fail(w, http.StatusInternalServerError, "failed to save message")
		return
	}
	if !stored {
		fail(w, http.StatusTooManyRequests, api.ErrInboxFull)
		return
	}
	for dev := range msgs {
		s.wake(dk(u.ID, dev))
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) subscribe(key string) chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	if s.waiters[key] == nil {
		s.waiters[key] = map[chan struct{}]struct{}{}
	}
	s.waiters[key][ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

func (s *Server) unsubscribe(key string, ch chan struct{}) {
	s.mu.Lock()
	delete(s.waiters[key], ch)
	if len(s.waiters[key]) == 0 {
		delete(s.waiters, key)
	}
	s.mu.Unlock()
}

func (s *Server) wake(key string) {
	s.mu.Lock()
	for ch := range s.waiters[key] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	s.mu.Unlock()
}

// handleInbox reports who has messages waiting for the calling device. With
// ?wait=N it holds the request until something arrives (or N seconds pass),
// so clients get messages at once without polling.
func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAs(w, r, nil)
	if p == nil {
		return
	}
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait < 0 {
		wait = 0
	}
	if wait > api.MaxWait {
		wait = api.MaxWait
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	ch := s.subscribe(dk(p.user.ID, p.dev))
	defer s.unsubscribe(dk(p.user.ID, p.dev), ch)
	for {
		senders, err := s.store.Senders(p.user.ID, p.dev)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
		left := time.Until(deadline)
		if len(senders) > 0 || left <= 0 {
			if senders == nil {
				senders = map[string]int{}
			}
			writeJSON(w, http.StatusOK, api.InboxResp{Senders: senders})
			return
		}
		// Re-check now and then: another relay instance may have stored a message.
		if left > waitRecheck {
			left = waitRecheck
		}
		t := time.NewTimer(left)
		select {
		case <-ch:
		case <-t.C:
		case <-r.Context().Done():
			t.Stop()
			return
		}
		t.Stop()
	}
}

func (s *Server) handleInboxFrom(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAs(w, r, nil)
	if p == nil {
		return
	}
	sender := r.PathValue("sender")
	if !api.ValidUsername(sender) {
		fail(w, http.StatusBadRequest, "bad user")
		return
	}
	msgs, err := s.store.Messages(p.user.ID, p.dev, sender, pageSize)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Messages are NOT deleted here: the client acks once it has saved them.
	out := make([]json.RawMessage, 0, len(msgs))
	size := 0
	for _, m := range msgs {
		if size += len(m.Payload); size > pageBytes && len(out) > 0 {
			break // the rest comes with the next fetch
		}
		item, err := json.Marshal(struct {
			ID  int64           `json:"id"`
			Msg json.RawMessage `json:"msg"`
		}{m.ID, m.Payload})
		if err != nil {
			continue
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r, 1<<16)
	if !ok {
		return
	}
	p := s.authenticateAs(w, r, body)
	if p == nil {
		return
	}
	var req api.AckReq
	if json.Unmarshal(body, &req) != nil || len(req.IDs) > maxAck {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if len(req.IDs) > 0 {
		if err := s.store.Ack(p.user.ID, p.dev, req.IDs); err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- devices ---

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAs(w, r, nil)
	if p == nil {
		return
	}
	rec := s.identityOf(w, p)
	if rec == nil {
		return
	}
	devs, err1 := s.store.Devices(p.user.ID)
	spks, err2 := s.store.SignedPreKeys(p.user.ID)
	if err1 != nil || err2 != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := api.DevicesResp{IdentityID: rec.ID}
	if len(rec.List) > 0 {
		var l pqc.DeviceList
		if json.Unmarshal(rec.List, &l) == nil {
			resp.List = &l
		}
	}
	for _, d := range devs {
		_, ready := spks[d.ID]
		resp.Devices = append(resp.Devices, api.DeviceInfo{ID: d.ID, Primary: d.Primary, Ready: ready})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSetDevices takes a newer device list. What makes it valid is the
// account identity's signature on it, which the relay checks like every
// client will; the relay cannot make one itself.
func (s *Server) handleSetDevices(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r, 1<<20)
	if !ok {
		return
	}
	p := s.authenticateAs(w, r, body)
	if p == nil {
		return
	}
	var l pqc.DeviceList
	if json.Unmarshal(body, &l) != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	rec := s.identityOf(w, p)
	if rec == nil {
		return
	}
	if l.Verify(rec.Identity, p.user.Name) != nil {
		fail(w, http.StatusForbidden, "device list is not signed by the account identity")
		return
	}
	canon, err := json.Marshal(&l)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if l.V == rec.ListV && bytes.Equal(canon, rec.List) {
		w.WriteHeader(http.StatusNoContent) // the same list again (a lost answer)
		return
	}
	linked := make([]Device, 0, len(l.Keys))
	for _, k := range l.Keys {
		linked = append(linked, Device{ID: pqc.IdentityID(k), Key: k})
	}
	stored, err := s.store.SetDeviceList(p.user.ID, l.V, canon, linked)
	if err != nil {
		log.Printf("set devices %s: %v", p.user.Name, err)
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !stored {
		fail(w, http.StatusConflict, "the relay already has this or a newer device list")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRetireDevice lets a linked device take itself out of service: its
// prekeys and waiting messages go, so nothing is sent to it any more.
func (s *Server) handleRetireDevice(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAs(w, r, nil)
	if p == nil {
		return
	}
	if p.primary() {
		fail(w, http.StatusBadRequest, "the first device cannot retire; release the identity instead")
		return
	}
	if err := s.store.ClearDevice(p.user.ID, p.dev); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- linking a device ---

// handleLinkRequest files a new device's request. Like a registration it
// takes a signature from an SSH key on the itter account, so that strangers
// cannot fill an account's few request slots.
func (s *Server) handleLinkRequest(w http.ResponseWriter, r *http.Request) {
	if !s.allowIP(w, r) {
		return
	}
	body, ok := readBody(w, r, 1<<20)
	if !ok {
		return
	}
	name := r.PathValue("user")
	var req api.LinkReq
	if json.Unmarshal(body, &req) != nil || !api.ValidUsername(name) || !deviceRE.MatchString(req.LinkID) || len(req.Tag) != sha512.Size {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if _, err := pqc.DecodeIdentityKey(req.DeviceKey); err != nil {
		fail(w, http.StatusBadRequest, "invalid device key")
		return
	}
	if d := s.now().Sub(time.Unix(req.TS, 0)); d > releaseSkew || d < -releaseSkew {
		w.Header().Set(api.TimeHeader, strconv.FormatInt(s.now().Unix(), 10))
		fail(w, http.StatusUnauthorized, api.ErrClockSkew)
		return
	}
	u, err := s.store.User(name)
	if err != nil {
		fail(w, http.StatusNotFound, "user not found on itter")
		return
	}
	rec, err := s.store.Identity(u.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if rec == nil {
		fail(w, http.StatusGone, api.ErrNoIdentity) // there is no first device to link to
		return
	}
	if !s.verifySSHBinding(u.ID, api.LinkPayload(name, req.LinkID, req.DeviceKey, req.TS), req.SSHSigs) {
		fail(w, http.StatusForbidden, "no valid signature from a non-RSA SSH key on this itter account")
		return
	}
	stored, err := s.store.PutLink(u.ID, &Link{ID: req.LinkID, DeviceKey: req.DeviceKey, Tag: req.Tag}, maxLinks)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !stored {
		fail(w, http.StatusTooManyRequests, "too many link requests are waiting for this account")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleLinkGet(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAs(w, r, nil)
	if p == nil {
		return
	}
	id := r.PathValue("id")
	if !deviceRE.MatchString(id) {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	l, err := s.store.Link(p.user.ID, id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if l == nil {
		fail(w, http.StatusNotFound, "no such link request")
		return
	}
	writeJSON(w, http.StatusOK, api.LinkInfo{DeviceKey: l.DeviceKey, Tag: l.Tag})
}

func (s *Server) handleLinkAnswer(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r, 1<<20)
	if !ok {
		return
	}
	p := s.authenticateAs(w, r, body)
	if p == nil {
		return
	}
	id := r.PathValue("id")
	var a api.LinkAnswer
	if !deviceRE.MatchString(id) || json.Unmarshal(body, &a) != nil || len(a.Result) == 0 {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := s.store.SetLinkResult(p.user.ID, id, a.Result); err != nil {
		fail(w, http.StatusNotFound, "no such link request")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleLinkResult is polled by the new device. It needs no login: the ID is
// derived from the one-time code, and the answer is checked with that code.
func (s *Server) handleLinkResult(w http.ResponseWriter, r *http.Request) {
	if !s.allowIP(w, r) {
		return
	}
	name, id := r.PathValue("user"), r.PathValue("id")
	if !api.ValidUsername(name) || !deviceRE.MatchString(id) {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := s.store.User(name)
	if err != nil {
		fail(w, http.StatusNotFound, "no such link request")
		return
	}
	l, err := s.store.Link(u.ID, id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if l == nil {
		fail(w, http.StatusNotFound, "no such link request")
		return
	}
	writeJSON(w, http.StatusOK, api.LinkAnswer{Result: l.Result})
}

// --- ignore list ---

func (s *Server) handleIgnoreList(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAs(w, r, nil)
	if p == nil {
		return
	}
	names, err := s.store.Ignored(p.user.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if names == nil {
		names = []string{}
	}
	writeJSON(w, http.StatusOK, api.IgnoreResp{Ignored: names})
}

func (s *Server) handleIgnoreSet(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAs(w, r, nil)
	if p == nil {
		return
	}
	peer := r.PathValue("peer")
	if !api.ValidUsername(peer) {
		fail(w, http.StatusBadRequest, "bad user")
		return
	}
	other, err := s.store.User(peer)
	if err != nil {
		fail(w, http.StatusNotFound, "no such user")
		return
	}
	if other.ID == p.user.ID {
		fail(w, http.StatusBadRequest, "you cannot ignore yourself")
		return
	}
	if err := s.store.SetIgnore(p.user, other, r.Method == http.MethodPut); err != nil {
		log.Printf("ignore %s: %v", p.user.Name, err)
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
