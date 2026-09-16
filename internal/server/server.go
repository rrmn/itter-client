package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"itter-cli/internal/api"
	"itter-cli/internal/pqc"
)

const (
	maxMsgSize    = 64 * 1024
	maxInboxQueue = 100
	msgTTL        = 7 * 24 * time.Hour
	maxWaitSec    = 30
	ratePerMin    = 60
)

var (
	usernameRE = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)
	errUnknown = errors.New("unknown user")
	errBadAuth = errors.New("authentication failed")
)

type account struct {
	Username  string        `json:"username"`
	SignPub   []byte        `json:"sign_pub"`
	DHPub     []byte        `json:"dh_pub"`
	SPKID     uint32        `json:"spk_id"`
	SPKDHPub  []byte        `json:"spk_dh_pub"`
	SPKKEMPub []byte        `json:"spk_kem_pub"`
	SPKSig    []byte        `json:"spk_sig"`
	OTPKs     []api.OTPKPub `json:"otpks"`
}

type storedMsg struct {
	TS   int64           `json:"ts"`
	Data json.RawMessage `json:"data"`
}

type Store struct {
	mu      sync.Mutex
	path    string
	Accts   map[string]*account                  `json:"accounts"`
	Inboxes map[string]map[string][]storedMsg    `json:"inboxes"`
	notify  map[string]chan struct{}             `json:"-"`
	rl      map[string]*rlState                  `json:"-"`
}

type rlState struct {
	count int
	reset time.Time
}

func Load(path string) *Store {
	st := &Store{
		path:    path,
		Accts:   map[string]*account{},
		Inboxes: map[string]map[string][]storedMsg{},
		notify:  map[string]chan struct{}{},
		rl:      map[string]*rlState{},
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, st)
	}
	if st.Accts == nil {
		st.Accts = map[string]*account{}
	}
	if st.Inboxes == nil {
		st.Inboxes = map[string]map[string][]storedMsg{}
	}
	return st
}

func (st *Store) saveLocked() {
	b, err := json.Marshal(st)
	if err != nil {
		log.Printf("save: %v", err)
		return
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("save: %v", err)
		return
	}
	_ = os.Rename(tmp, st.path)
}

func (st *Store) allow(ip string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	e := st.rl[ip]
	now := time.Now()
	if e == nil || now.After(e.reset) {
		st.rl[ip] = &rlState{count: 1, reset: now.Add(time.Minute)}
		return true
	}
	e.count++
	return e.count <= ratePerMin
}

func (st *Store) authenticate(r *http.Request, username string) (*account, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	a, ok := st.Accts[username]
	if !ok {
		return nil, errUnknown
	}
	minute, err := strconv.ParseInt(r.Header.Get(api.MinuteHeader), 10, 64)
	if err != nil {
		return nil, errBadAuth
	}
	if d := time.Now().Unix()/60 - minute; d < -1 || d > 1 {
		return nil, errBadAuth
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get(api.AuthHeader))
	if err != nil {
		return nil, errBadAuth
	}
	if !ed25519.Verify(ed25519.PublicKey(a.SignPub), api.AuthPayload(r.Method, r.URL.Path, minute), sig) {
		return nil, errBadAuth
	}
	return a, nil
}

func (st *Store) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req api.RegReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !usernameRE.MatchString(req.Username) {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(req.SignPub), api.RegPayload(req.Username, req.SignPub, req.DHPub), req.Sig) {
		http.Error(w, "bad signature", http.StatusForbidden)
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if a, ok := st.Accts[req.Username]; ok {
		if !bytes.Equal(a.SignPub, req.SignPub) {
			http.Error(w, "username taken", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	st.Accts[req.Username] = &account{Username: req.Username, SignPub: req.SignPub, DHPub: req.DHPub}
	st.saveLocked()
	w.WriteHeader(http.StatusCreated)
}

func (st *Store) handleUploadKeys(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	a, err := st.authenticate(r, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var up api.KeysUpload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&up); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(a.SignPub), pqc.SPKSigningPayload(up.SPKID, up.SPKDHPub, up.SPKKEMPub), up.SPKSig) {
		http.Error(w, "signed prekey signature invalid", http.StatusForbidden)
		return
	}
	st.mu.Lock()
	a.SPKID, a.SPKDHPub, a.SPKKEMPub, a.SPKSig = up.SPKID, up.SPKDHPub, up.SPKKEMPub, up.SPKSig
	a.OTPKs = append(a.OTPKs, up.OTPKs...)
	if len(a.OTPKs) > 200 {
		a.OTPKs = a.OTPKs[len(a.OTPKs)-200:]
	}
	st.saveLocked()
	st.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (st *Store) handleGetBundle(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	st.mu.Lock()
	a, ok := st.Accts[user]
	if !ok || a.SPKKEMPub == nil {
		st.mu.Unlock()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	b := pqc.PublicBundle{
		Username: user, SignPub: a.SignPub, IKDHPub: a.DHPub,
		SPKID: a.SPKID, SPKDHPub: a.SPKDHPub, SPKKEMPub: a.SPKKEMPub, SPKSig: a.SPKSig,
	}
	if len(a.OTPKs) > 0 {
		k := a.OTPKs[0]
		a.OTPKs = a.OTPKs[1:]
		b.OTPKID, b.OTPKDHPub, b.OTPKKEMPub = k.ID, k.DHPub, k.KEMPub
		st.saveLocked()
	}
	st.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b)
}

func (st *Store) handlePostMsg(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !st.allow(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMsgSize))
	if err != nil {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return
	}
	var wm pqc.WireMsg
	if err := json.Unmarshal(raw, &wm); err != nil ||
		(wm.Type != pqc.WireInitial && wm.Type != pqc.WireEnvelope) || len(wm.Payload) == 0 {
		http.Error(w, "malformed message", http.StatusBadRequest)
		return
	}
	
	st.mu.Lock()
	if _, ok := st.Accts[user]; !ok {
		st.mu.Unlock()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if st.Inboxes[user] == nil {
		st.Inboxes[user] = map[string][]storedMsg{}
	}
	if len(st.Inboxes[user][wm.From]) >= maxInboxQueue {
		st.mu.Unlock()
		http.Error(w, "mailbox full for this sender", http.StatusInsufficientStorage)
		return
	}
	st.Inboxes[user][wm.From] = append(st.Inboxes[user][wm.From], storedMsg{TS: time.Now().Unix(), Data: json.RawMessage(raw)})
	if ch := st.notify[user]; ch != nil {
		close(ch)
		delete(st.notify, user)
	}
	st.saveLocked()
	st.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
}

func (st *Store) handleSenders(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if _, err := st.authenticate(r, user); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait > maxWaitSec {
		wait = maxWaitSec
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)

	respond := func() {
		out := make(api.SendersResp)
		for sender, msgs := range st.Inboxes[user] {
			if len(msgs) > 0 {
				out[sender] = len(msgs)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}

	for {
		st.mu.Lock()
		count := 0
		for _, msgs := range st.Inboxes[user] {
			count += len(msgs)
		}
		if count > 0 || wait <= 0 {
			respond()
			st.mu.Unlock()
			return
		}
		ch := st.notify[user]
		if ch == nil {
			ch = make(chan struct{})
			st.notify[user] = ch
		}
		st.mu.Unlock()

		remain := time.Until(deadline)
		if remain <= 0 {
			st.mu.Lock()
			respond()
			st.mu.Unlock()
			return
		}
		t := time.NewTimer(remain)
		select {
		case <-ch:
			t.Stop()
		case <-t.C:
			st.mu.Lock()
			respond()
			st.mu.Unlock()
			return
		case <-r.Context().Done():
			t.Stop()
			return
		}
	}
}

func (st *Store) handleInboxFrom(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	sender := r.PathValue("sender")
	if _, err := st.authenticate(r, user); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	st.mu.Lock()
	msgs := st.Inboxes[user][sender]
	out := make([]json.RawMessage, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, m.Data)
	}
	delete(st.Inboxes[user], sender)
	if len(msgs) > 0 {
		st.saveLocked()
	}
	st.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (st *Store) sweeper() {
	for range time.Tick(time.Minute) {
		cut := time.Now().Add(-msgTTL).Unix()
		st.mu.Lock()
		changed := false
		for u, senders := range st.Inboxes {
			for s, inbox := range senders {
				var kept []storedMsg
				for _, m := range inbox {
					if m.TS > cut {
						kept = append(kept, m)
					}
				}
				if len(kept) != len(inbox) {
					if len(kept) == 0 {
						delete(st.Inboxes[u], s)
					} else {
						st.Inboxes[u][s] = kept
					}
					changed = true
				}
			}
		}
		if changed {
			st.saveLocked()
		}
		st.mu.Unlock()
	}
}

func Run(addr, path string) error {
	st := Load(path)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/register", st.handleRegister)
	mux.HandleFunc("PUT /v1/keys/{user}", st.handleUploadKeys)
	mux.HandleFunc("GET /v1/keys/{user}", st.handleGetBundle)
	mux.HandleFunc("POST /v1/msg/{user}", st.handlePostMsg)
	mux.HandleFunc("GET /v1/senders/{user}", st.handleSenders)
	mux.HandleFunc("GET /v1/inbox/{user}/from/{sender}", st.handleInboxFrom)
	go st.sweeper()
	log.Printf("itter-relay listening on %s (state: %s)", addr, path)
	return http.ListenAndServe(addr, mux)
}