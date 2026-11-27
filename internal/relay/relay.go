// Package relay is the client side of the itter DM relay API.
package relay

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"itter-cli/internal/api"
	"itter-cli/internal/pqc"
)

// maxResponse bounds what the client will read from the relay.
const maxResponse = 64 << 20

type Client struct {
	Base string
	// Name says where requests go, for people ("" = Base).
	Name string
	// Tunnel is the SSH connection requests travel through (nil: plain HTTP
	// to Base).
	Tunnel *Tunnel
	HC     *http.Client // ordinary requests
	Long   *http.Client // long-polls
	// Sessions keeps this device's session with the relay between runs, so
	// that not every command has to open one (that takes a full signature).
	// Without it a session lives as long as the Client.
	Sessions SessionStore

	mu       sync.Mutex // also held while a session is being opened
	sessions map[string]*Session
}

// Session is what a device needs to make authenticated requests: the ticket
// that names its session and the key requests are MACed with. The key was
// agreed with the relay and never travels.
type Session struct {
	Relay    string `json:"relay"` // Client.Where() of the relay it belongs to
	Username string `json:"username"`
	Device   string `json:"device"`
	Ticket   string `json:"ticket"`
	Key      []byte `json:"key"`
	Expires  int64  `json:"expires"` // unix seconds
}

// SessionStore keeps one session. SaveSession(nil) forgets it.
type SessionStore interface {
	LoadSession() *Session
	SaveSession(*Session) error
}

// renewBefore is how long before its end a session is no longer used: a
// long-poll that starts now must not outlive it.
const renewBefore = 10 * time.Minute

// ErrSessionAnswer means the answer to opening a session did not fit the
// request: it was damaged on the way, or it is not the relay's.
var ErrSessionAnswer = errors.New("the answer to opening a session does not fit the request")

// Transport, when set, replaces the default HTTP transport of new clients
// (tests use it to simulate an unreliable network).
var Transport http.RoundTripper

// Where says where requests go, in words for the user.
func (c *Client) Where() string {
	if c.Name != "" {
		return c.Name
	}
	return c.Base
}

func New(base string) *Client {
	return &Client{
		Base: base,
		HC:   &http.Client{Timeout: overall, Transport: transport(20 * time.Second)},
		Long: &http.Client{Timeout: overall + api.MaxWait*time.Second, Transport: transport((api.MaxWait + 15) * time.Second)},
	}
}

// overall bounds one request including its body. It is generous on purpose:
// a first message is ~120 KB and a page of them 1 MB, which takes a while on
// a slow link. An unreachable relay is noticed much sooner, see transport.
const overall = 3 * time.Minute

// transport returns an HTTP transport that gives up quickly when the relay
// cannot be reached or does not answer (connect, TLS, response headers), but
// puts no deadline on moving a body that is making progress.
func transport(answer time.Duration) http.RoundTripper {
	if Transport != nil {
		return Transport
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	t.TLSHandshakeTimeout = 10 * time.Second
	t.ResponseHeaderTimeout = answer
	return t
}

// HTTPError is a non-2xx relay response.
type HTTPError struct {
	Status     int
	Body       string
	ServerTime int64 // set when the relay says our clock is off
}

func (e *HTTPError) Error() string { return fmt.Sprintf("relay: %d: %s", e.Status, e.Body) }

// Status returns the HTTP status of a relay error, or 0 for anything else
// (network failures in particular).
func Status(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

// Is reports whether err is the relay's error with the given body text.
func Is(err error, body string) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Body == body
}

func (c *Client) do(hc *http.Client, req *http.Request, out any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		he := &HTTPError{Status: resp.StatusCode, Body: string(bytes.TrimSpace(b))}
		he.ServerTime, _ = strconv.ParseInt(resp.Header.Get(api.TimeHeader), 10, 64)
		return he
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(out)
	}
	return nil
}

func (c *Client) newReq(method, path string, body []byte) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.Base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func newNonce() (string, error) {
	var nb [16]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nb[:]), nil
}

// Authorize makes req a request of the session: the ticket, the time, a fresh
// nonce and a MAC over all that matters. uri is the path with its query.
func (s *Session) Authorize(req *http.Request, uri string, body []byte) error {
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	ts := time.Now().Unix()
	bh := sha512.Sum512(body)
	req.Header.Set(api.SessionHeader, s.Ticket)
	req.Header.Set(api.TimeHeader, strconv.FormatInt(ts, 10))
	req.Header.Set(api.NonceHeader, nonce)
	req.Header.Set(api.AuthHeader, base64.StdEncoding.EncodeToString(api.RequestMAC(s.Key, req.Method, uri, ts, nonce, bh[:])))
	return nil
}

// Auth identifies the caller of an authenticated request: an account and
// the key of the device that is calling.
type Auth struct {
	Username string
	ID       *pqc.Identity
}

func (s *Session) fits(c *Client, a Auth, dev string) bool {
	return s != nil && s.Relay == c.Where() && s.Device == dev && strings.EqualFold(s.Username, a.Username) &&
		s.Ticket != "" && len(s.Key) == pqc.SessionKeySize && time.Now().Unix() < s.Expires-int64(renewBefore/time.Second)
}

// SessionFor returns the device's session with the relay: the one in use,
// the one kept from an earlier run, or a new one.
func (c *Client) SessionFor(a Auth) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dev := pqc.IdentityID(a.ID.Pub.Encode())
	who := strings.ToLower(a.Username) + "/" + dev
	if c.sessions == nil {
		c.sessions = map[string]*Session{}
	}
	if c.sessions[who] == nil && c.Sessions != nil {
		c.sessions[who] = c.Sessions.LoadSession()
	}
	if s := c.sessions[who]; s.fits(c, a, dev) {
		return s, nil
	}
	s, err := c.openSession(a, dev)
	if err != nil {
		return nil, err
	}
	c.sessions[who] = s
	if c.Sessions != nil {
		_ = c.Sessions.SaveSession(s) // if it cannot be kept, the next run opens another
	}
	return s, nil
}

// dropSession forgets a session the relay no longer knows.
func (c *Client) dropSession(s *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	who := strings.ToLower(s.Username) + "/" + s.Device
	if c.sessions[who] != s {
		return // someone else already replaced it
	}
	delete(c.sessions, who)
	if c.Sessions != nil {
		_ = c.Sessions.SaveSession(nil)
	}
}

// openSession proves to the relay which device this is, once, and agrees on
// a key for the requests that follow. The proof is the device key's full
// signature (the hash-based part included) over one-time public keys; the
// relay's answer can only be opened with their private halves.
func (c *Client) openSession(a Auth, dev string) (*Session, error) {
	offer, err := pqc.NewSessionOffer()
	if err != nil {
		return nil, err
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	ts := time.Now().Unix()
	sig, err := a.ID.Sign.SignFull(api.SessionPayload(a.Username, dev, ts, nonce, offer.Public()), "relay-session")
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(api.SessionReq{Device: dev, TS: ts, Nonce: nonce, Offer: offer.Public(), Sig: sig})
	req, err := c.newReq("POST", "/v1/session/"+a.Username, b)
	if err != nil {
		return nil, err
	}
	var resp api.SessionResp
	if err := c.do(c.HC, req, &resp); err != nil {
		return nil, err
	}
	if resp.Ticket == "" || len(resp.Ticket) > 1024 || resp.Expires <= ts {
		return nil, ErrSessionAnswer
	}
	secret, err := offer.Open(resp.Answer, []byte(resp.Ticket))
	if err != nil {
		return nil, ErrSessionAnswer
	}
	key, err := pqc.UnwrapSessionKey(secret, []byte(resp.Ticket), resp.Box)
	if err != nil {
		return nil, ErrSessionAnswer
	}
	return &Session{Relay: c.Where(), Username: a.Username, Device: dev, Ticket: resp.Ticket, Key: key, Expires: resp.Expires}, nil
}

// authed performs a request of this device's session.
func (c *Client) authed(hc *http.Client, a Auth, method, path string, body []byte, hdr map[string]string, out any) error {
	for attempt := 0; ; attempt++ {
		sess, err := c.SessionFor(a)
		if err != nil {
			return err
		}
		req, err := c.newReq(method, path, body)
		if err != nil {
			return err
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if err := sess.Authorize(req, path, body); err != nil {
			return err
		}
		err = c.do(hc, req, out)
		if attempt == 0 && Status(err) == http.StatusUnauthorized && Is(err, api.ErrSessionGone) {
			c.dropSession(sess) // it ran out, or the relay was restarted: open a new one
			continue
		}
		return err
	}
}

// Register binds the identity to the account and returns the account name
// as itter spells it.
func (c *Client) Register(r *api.RegReq) (string, error) {
	b, _ := json.Marshal(r)
	req, err := c.newReq("PUT", "/v1/register", b)
	if err != nil {
		return "", err
	}
	var resp api.RegResp
	if err := c.do(c.HC, req, &resp); err != nil {
		return "", err
	}
	return resp.Username, nil
}

func (c *Client) release(r *api.ReleaseReq) error {
	b, _ := json.Marshal(r)
	req, err := c.newReq("DELETE", "/v1/register", b)
	if err != nil {
		return err
	}
	return c.do(c.HC, req, nil)
}

// Release removes the identity from the relay, authorised by the identity
// itself. Only the account's first device holds that key.
func (c *Client) Release(a Auth) error {
	ts := time.Now().Unix()
	sig, err := a.ID.Sign.SignFull(api.ReleasePayload(a.Username, a.ID.Pub.Encode(), ts), "dm-release")
	if err != nil {
		return err
	}
	return c.release(&api.ReleaseReq{Username: a.Username, TS: ts, Sig: sig})
}

// ReleaseWithCode removes an account's identity using its recovery code
// (lost device). The code stays here: what is sent is a signature made with
// it, over the account's name and the time.
func (c *Client) ReleaseWithCode(username string, code []byte) error {
	ts := time.Now().Unix()
	sig, err := pqc.RecoverySign(code, api.RecoverPayload(username, ts))
	if err != nil {
		return err
	}
	return c.release(&api.ReleaseReq{Username: username, TS: ts, RecoverySig: sig})
}

func (c *Client) UploadKeys(a Auth, spk *pqc.PreKeyPublic, spkSig []byte, otpks []*pqc.PreKeyPublic) error {
	b, _ := json.Marshal(api.KeysUpload{SPK: spk, SPKSig: spkSig, OTPKs: otpks})
	return c.authed(c.HC, a, "PUT", "/v1/keys/"+a.Username, b, nil, nil)
}

// Directory fetches what the relay lists for an account: identity, signed
// device list and each device's signed prekey. Anyone may ask; it uses up
// nothing. The caller has to verify all of it.
func (c *Client) Directory(username string) (*api.Directory, error) {
	req, err := c.newReq("GET", "/v1/keys/"+username, nil)
	if err != nil {
		return nil, err
	}
	var d api.Directory
	if err := c.do(c.HC, req, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Claim fetches the directory entry including a one-time prekey for each of
// the named devices (all, if none are named), where the relay has one to spare.
func (c *Client) Claim(a Auth, username string, devices []string) (*api.Directory, error) {
	b, _ := json.Marshal(api.ClaimReq{Devices: devices})
	var d api.Directory
	if err := c.authed(c.HC, a, "POST", "/v1/keys/"+username+"/claim", b, nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// KeyCount reports how many of this device's one-time prekeys the relay has left.
func (c *Client) KeyCount(a Auth) (int, error) {
	var r api.KeyCountResp
	err := c.authed(c.HC, a, "GET", "/v1/keys/"+a.Username+"/count", nil, nil, &r)
	return r.OTPKs, err
}

// Send posts already-encrypted messages, one per device of the recipient. It
// is used for fresh sends and for outbox retries alike — a retry must NEVER
// re-encrypt (that would advance the ratchet twice). toID names the account
// identity they were encrypted for.
func (c *Client) Send(a Auth, to, toID string, msgs map[string][]byte) error {
	req := api.SendReq{ToID: toID, Msgs: make(map[string]json.RawMessage, len(msgs))}
	for dev, m := range msgs {
		req.Msgs[dev] = m
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return c.authed(c.HC, a, "POST", "/v1/msg/"+to, b, nil, nil)
}

// Devices lists the account's own devices.
func (c *Client) Devices(a Auth) (*api.DevicesResp, error) {
	var r api.DevicesResp
	if err := c.authed(c.HC, a, "GET", "/v1/devices/"+a.Username, nil, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// SetDevices publishes a newer device list, signed by the account identity.
func (c *Client) SetDevices(a Auth, l *pqc.DeviceList) error {
	b, _ := json.Marshal(l)
	return c.authed(c.HC, a, "PUT", "/v1/devices/"+a.Username, b, nil, nil)
}

// RetireDevice takes the calling (linked) device out of service on the relay.
func (c *Client) RetireDevice(a Auth) error {
	return c.authed(c.HC, a, "DELETE", "/v1/devices/"+a.Username, nil, nil, nil)
}

// LinkRequest files a new device's request to be linked.
func (c *Client) LinkRequest(username string, r *api.LinkReq) error {
	b, _ := json.Marshal(r)
	req, err := c.newReq("POST", "/v1/link/"+username, b)
	if err != nil {
		return err
	}
	return c.do(c.HC, req, nil)
}

// LinkInfo shows the first device a link request.
func (c *Client) LinkInfo(a Auth, linkID string) (*api.LinkInfo, error) {
	var info api.LinkInfo
	if err := c.authed(c.HC, a, "GET", "/v1/link/"+a.Username+"/"+linkID, nil, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// LinkAnswer stores the first device's answer for the new device to pick up.
func (c *Client) LinkAnswer(a Auth, linkID string, result []byte) error {
	b, _ := json.Marshal(api.LinkAnswer{Result: result})
	return c.authed(c.HC, a, "PUT", "/v1/link/"+a.Username+"/"+linkID, b, nil, nil)
}

// LinkResult returns the answer to a link request: nil while there is none yet.
func (c *Client) LinkResult(username, linkID string) ([]byte, error) {
	req, err := c.newReq("GET", "/v1/link/"+username+"/"+linkID+"/result", nil)
	if err != nil {
		return nil, err
	}
	var a api.LinkAnswer
	if err := c.do(c.HC, req, &a); err != nil {
		return nil, err
	}
	return a.Result, nil
}

// Ignored lists who the account ignores (itter's own ignore list).
func (c *Client) Ignored(a Auth) ([]string, error) {
	var r api.IgnoreResp
	if err := c.authed(c.HC, a, "GET", "/v1/ignore/"+a.Username, nil, nil, &r); err != nil {
		return nil, err
	}
	return r.Ignored, nil
}

// SetIgnore starts or stops ignoring peer.
func (c *Client) SetIgnore(a Auth, peer string, ignore bool) error {
	method := "DELETE"
	if ignore {
		method = "PUT"
	}
	return c.authed(c.HC, a, method, "/v1/ignore/"+a.Username+"/"+peer, nil, nil, nil)
}

// Inbox reports who has messages waiting. With wait > 0 the relay holds the
// request until something arrives or wait seconds pass.
func (c *Client) Inbox(a Auth, wait int) (map[string]int, error) {
	hc, path := c.HC, "/v1/inbox/"+a.Username
	if wait > 0 {
		hc, path = c.Long, path+"?wait="+strconv.Itoa(wait)
	}
	var r api.InboxResp
	if err := c.authed(hc, a, "GET", path, nil, nil, &r); err != nil {
		return nil, err
	}
	return r.Senders, nil
}

// InboxFrom fetches waiting messages from one sender, oldest first. The
// relay keeps them until Ack.
func (c *Client) InboxFrom(a Auth, sender string) ([]api.InboxItem, error) {
	var items []api.InboxItem
	if err := c.authed(c.HC, a, "GET", "/v1/inbox/"+a.Username+"/from/"+sender, nil, nil, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// Ack tells the relay that messages are safely stored and can be deleted.
func (c *Client) Ack(a Auth, ids []int64) error {
	b, _ := json.Marshal(api.AckReq{IDs: ids})
	return c.authed(c.HC, a, "POST", "/v1/inbox/"+a.Username+"/ack", b, nil, nil)
}
