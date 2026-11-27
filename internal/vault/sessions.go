package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"itter-cli/internal/pqc"
)

const (
	maxPrevious       = 4   // older sessions kept per device of a contact
	maxSeenHandshakes = 200 // per contact
)

// ErrNoSession means there is no usable session with the contact's device.
var ErrNoSession = errors.New("no session")

// A session is with one device of a contact. Sessions and Previous are keyed
// by "<peer>/<device id>"; account names cannot contain a slash.
func skey(peer, dev string) string { return peer + "/" + dev }

func devID(key []byte) string { return pqc.IdentityID(key) }

// validDevice reports whether key belongs to peer: it is the identity on
// record (the first device) or on the contact's signed device list. Callers
// hold v.Mu.
func (v *Vault) validDevice(peer string, key []byte) bool {
	c := v.Contacts[peer]
	if c == nil || len(c.Identity) == 0 {
		return false
	}
	if same(c.Identity, key) {
		return true
	}
	for _, k := range c.Devices {
		if same(k, key) {
			return true
		}
	}
	return false
}

// peerKeys lists the session keys that belong to peer. Callers hold v.Mu.
func (v *Vault) peerKeys(peer string) []string {
	seen := map[string]bool{}
	for k := range v.Sessions {
		if strings.HasPrefix(k, peer+"/") {
			seen[k] = true
		}
	}
	for k := range v.Previous {
		if strings.HasPrefix(k, peer+"/") {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// current returns the active session with one device of peer, if that device
// still belongs to the contact. Callers hold v.Mu.
func (v *Vault) current(peer, dev string) *pqc.Session {
	s := v.Sessions[skey(peer, dev)]
	if s == nil || !v.validDevice(peer, s.TheirIdentity) {
		return nil
	}
	return s
}

// dropStaleSessions removes every session with peer whose device no longer
// belongs to the contact: after an identity change, or when a device was
// taken off the contact's list. Without this, whoever holds OLD keys (a
// stolen or retired device) could keep sending, and a decrypted message would
// even make the old session current again. Callers hold v.Mu.
func (v *Vault) dropStaleSessions(peer string) {
	for _, k := range v.peerKeys(peer) {
		if s := v.Sessions[k]; s != nil && !v.validDevice(peer, s.TheirIdentity) {
			delete(v.Sessions, k)
		}
		var kept []*pqc.Session
		for _, s := range v.Previous[k] {
			if v.validDevice(peer, s.TheirIdentity) {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			delete(v.Previous, k)
		} else {
			v.Previous[k] = kept
		}
	}
}

// archive moves a device's current session to its previous list. Callers hold v.Mu.
func (v *Vault) archive(k string) {
	cur := v.Sessions[k]
	if cur == nil {
		return
	}
	prev := append([]*pqc.Session{cur}, v.Previous[k]...)
	if len(prev) > maxPrevious {
		prev = prev[:maxPrevious]
	}
	v.Previous[k] = prev
	delete(v.Sessions, k)
}

// SessionDevices lists the devices of peer a message can be encrypted for
// right now.
func (v *Vault) SessionDevices(peer string) []string {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	var out []string
	for _, k := range v.peerKeys(peer) {
		dev := strings.TrimPrefix(k, peer+"/")
		if v.current(peer, dev) != nil {
			out = append(out, dev)
		}
	}
	return out
}

// HadSessionWith reports whether there is, or was, a session with one device
// of peer. If not, a message from it that cannot be read is not a broken
// session: its handshake never arrived.
func (v *Vault) HadSessionWith(peer, dev string) bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	k := skey(peer, dev)
	return v.Sessions[k] != nil || len(v.Previous[k]) > 0
}

// HasSession reports whether there is a session with any device of peer.
func (v *Vault) HasSession(peer string) bool { return len(v.SessionDevices(peer)) > 0 }

// InstallSession makes s the active session with the device it was made
// with. The session it replaces is kept for a while: messages already in
// flight still decrypt. The device must belong to the contact.
func (v *Vault) InstallSession(peer string, s *pqc.Session) error {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	if !v.validDevice(peer, s.TheirIdentity) {
		return errors.New("session does not match the identity on record for @" + peer)
	}
	k := skey(peer, devID(s.TheirIdentity))
	v.archive(k)
	v.Sessions[k] = s
	return nil
}

// RetireSession sets the active sessions with peer aside so that the next
// message starts fresh handshakes. Late messages from the retired sessions
// still decrypt. Used when the relay reports that the peer's identity changed.
func (v *Vault) RetireSession(peer string) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	for _, k := range v.peerKeys(peer) {
		v.archive(k)
	}
}

// ResetSessions forgets every session with peer (the user asked for a clean
// start, typically because a session is stuck). It reports whether there
// was anything to forget.
func (v *Vault) ResetSessions(peer string) bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	keys := v.peerKeys(peer)
	for _, k := range keys {
		delete(v.Sessions, k)
		delete(v.Previous, k)
	}
	return len(keys) > 0
}

// Seal encrypts payload for one device of peer with its active session. It
// returns the relay message and, if the message carries a handshake, that
// handshake's ID.
func (v *Vault) Seal(peer, dev string, payload []byte) (*pqc.WireMsg, []byte, error) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	s := v.current(peer, dev)
	if s == nil {
		return nil, nil, ErrNoSession
	}
	w, err := s.Seal(v.Username, payload)
	if err != nil {
		return nil, nil, err
	}
	w.Dev = devID(v.Identity.Pub.Encode())
	if w.Type == pqc.WireInitial {
		return w, s.HandshakeID, nil
	}
	return w, nil, nil
}

// HandshakeDelivered records that the relay took a message carrying this
// handshake: the session stops attaching it.
func (v *Vault) HandshakeDelivered(peer, dev string, hsID []byte) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	k := skey(peer, dev)
	for _, s := range append([]*pqc.Session{v.Sessions[k]}, v.Previous[k]...) {
		if s != nil && len(hsID) > 0 && bytes.Equal(s.HandshakeID, hsID) {
			s.HandshakeDelivered()
		}
	}
}

// sessionsFor lists the sessions that may decrypt a message from peer's
// device dev: current first, then previous. With an unknown device every
// session with peer is a candidate. Callers hold v.Mu.
func (v *Vault) sessionsFor(peer, dev string) (out []*pqc.Session, keys []string) {
	ks := []string{skey(peer, dev)}
	if dev == "" || (v.Sessions[ks[0]] == nil && len(v.Previous[ks[0]]) == 0) {
		ks = v.peerKeys(peer)
	}
	for _, k := range ks {
		for _, s := range append([]*pqc.Session{v.Sessions[k]}, v.Previous[k]...) {
			if s != nil && v.validDevice(peer, s.TheirIdentity) {
				out, keys = append(out, s), append(keys, k)
			}
		}
	}
	return out, keys
}

// Open decrypts an envelope from peer; dev is the relay's hint which device
// sent it. The session that decrypts it becomes that device's active one
// (that is how crossing handshakes converge). It returns pqc.ErrDuplicate for
// a message that was already received, and pqc.ErrDecrypt when no session can
// read it.
func (v *Vault) Open(peer, dev string, env []byte) ([]byte, error) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	dup := false
	sessions, keys := v.sessionsFor(peer, dev)
	for i, s := range sessions {
		pt, err := s.Decrypt(env)
		if err == nil {
			v.promote(keys[i], s)
			return pt, nil
		}
		if errors.Is(err, pqc.ErrDuplicate) {
			dup = true
		}
	}
	if dup {
		return nil, pqc.ErrDuplicate
	}
	return nil, pqc.ErrDecrypt
}

// promote makes s the active session of its device. Callers hold v.Mu.
func (v *Vault) promote(k string, s *pqc.Session) {
	if v.Sessions[k] == s {
		return
	}
	var rest []*pqc.Session
	for _, p := range v.Previous[k] {
		if p != s {
			rest = append(rest, p)
		}
	}
	v.Previous[k] = rest
	v.archive(k)
	v.Sessions[k] = s
}

// KnownHandshake reports whether a session created by this handshake exists.
func (v *Vault) KnownHandshake(peer string, hsID []byte) bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	sessions, _ := v.sessionsFor(peer, "")
	for _, s := range sessions {
		if len(hsID) > 0 && bytes.Equal(s.HandshakeID, hsID) {
			return true
		}
	}
	return false
}

// HandshakeSeen reports whether a handshake from peer was processed before.
func (v *Vault) HandshakeSeen(peer string, hsID []byte) bool {
	h := hex.EncodeToString(hsID)
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil {
		return false
	}
	for _, x := range c.Handshakes {
		if x == h {
			return true
		}
	}
	return false
}

// MarkHandshake records a handshake from peer as processed. The memory is
// per contact, so nobody can push another contact's handshakes out of it.
func (v *Vault) MarkHandshake(peer string, hsID []byte) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil {
		return
	}
	c.Handshakes = append(c.Handshakes, hex.EncodeToString(hsID))
	if len(c.Handshakes) > maxSeenHandshakes {
		c.Handshakes = append([]string(nil), c.Handshakes[len(c.Handshakes)-maxSeenHandshakes:]...)
	}
}
