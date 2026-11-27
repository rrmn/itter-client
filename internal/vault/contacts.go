package vault

import (
	"errors"
	"sort"
	"time"

	"itter-cli/internal/pqc"
)

// Contact is what this device knows about a peer's identity. Trust belongs
// here, not on a session: sessions come and go, the identity is what the
// user verified.
//
// An identity never changes under the user: once one is on record, a
// different one is only a candidate (Pending) until the user accepts it.
type Contact struct {
	Identity  []byte `json:"identity,omitempty"` // the identity we talk to (trust on first use)
	Verified  bool   `json:"verified"`           // the user compared safety numbers
	FirstSeen int64  `json:"first_seen"`         // unix time
	// Pending is a different identity that claims to be this contact; the
	// messages that came with it wait in Held, unread.
	Pending []byte   `json:"pending,omitempty"`
	Held    [][]byte `json:"held,omitempty"`
	// Announced is the pending identity the user has already been told about.
	Announced []byte `json:"announced,omitempty"`
	LastAlert int64  `json:"last_alert,omitempty"` // last "impersonation attempt" notice
	// Handshakes remembers processed handshake IDs, so a relay cannot replay
	// an old handshake to resurrect a stale session.
	Handshakes []string `json:"handshakes,omitempty"`

	// Devices are the keys of the contact's linked devices, taken from their
	// device list of version ListV, which Identity signed. (The first device
	// needs no entry: its key is Identity.) A list older than ListV is never
	// accepted again, so a removed device stays removed.
	ListV   uint64   `json:"list_v,omitempty"`
	Devices [][]byte `json:"devices,omitempty"`
	// Reach names the devices that could be written to when the relay's
	// directory was last looked at: every message goes to all of them.
	Reach []string `json:"reach,omitempty"`
}

// IdentityStatus is the outcome of seeing an identity for a contact.
type IdentityStatus int

const (
	IdentityNew     IdentityStatus = iota // first contact: now remembered
	IdentityKnown                         // same as before
	IdentityBlocked                       // differs from the one on record: pending until `accept`
)

// Held messages per contact are bounded in number and in size (a first
// message carries a ~120 KB handshake).
const (
	maxHeld      = 40
	maxHeldBytes = 2 << 20
)

func same(a, b []byte) bool { return pqc.IdentityEqual(a, b) }

// Observe records an identity that the relay's directory lists for peer (a
// verified key bundle). The first one is remembered; a different one later
// becomes pending and is NOT used.
func (v *Vault) Observe(peer string, identity []byte) IdentityStatus {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil {
		c = &Contact{FirstSeen: time.Now().Unix()}
		v.Contacts[peer] = c
	}
	switch {
	case len(c.Identity) == 0:
		c.Identity, c.Pending, c.Held, c.Announced = append([]byte(nil), identity...), nil, nil, nil
		return IdentityNew
	case same(c.Identity, identity):
		return IdentityKnown
	}
	if !same(c.Pending, identity) {
		if len(c.Pending) > 0 {
			c.Held = nil // held for another candidate that is no longer listed
		}
		// What is held without a candidate came from a device that was not
		// on record: most likely one of this new identity's. It stays.
		c.Pending, c.Announced = append([]byte(nil), identity...), nil
	}
	return IdentityBlocked
}

// HasDeviceID reports whether dev names the first device of the identity on
// record for peer, or one of the devices on their list.
func (v *Vault) HasDeviceID(peer, dev string) bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil || len(c.Identity) == 0 || dev == "" {
		return false
	}
	if devID(c.Identity) == dev {
		return true
	}
	for _, k := range c.Devices {
		if devID(k) == dev {
			return true
		}
	}
	return false
}

// Propose notes an identity that claims to be peer but is not (yet) the one
// on record: from a handshake that was correctly signed by that identity.
// Nothing is trusted or used; the caller checks it against the relay's
// directory and, for a known contact, waits for the user.
func (v *Vault) Propose(peer string, identity []byte) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil {
		c = &Contact{FirstSeen: time.Now().Unix()}
		v.Contacts[peer] = c
	}
	if !same(c.Pending, identity) {
		c.Pending, c.Held, c.Announced = append([]byte(nil), identity...), nil, nil
	}
}

// Hold keeps a raw relay message that arrived with a contact's pending
// identity. It returns how many are held now, and false when the message
// was dropped because the hold queue is full.
func (v *Vault) Hold(peer string, raw []byte) (int, bool) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil || len(c.Pending) == 0 {
		return 0, false
	}
	size := len(raw)
	for _, h := range c.Held {
		size += len(h)
	}
	if len(c.Held) >= maxHeld || (size > maxHeldBytes && len(c.Held) > 0) {
		return len(c.Held), false
	}
	c.Held = append(c.Held, append([]byte(nil), raw...))
	return len(c.Held), true
}

// HoldAside keeps a raw relay message from a known contact whose device is
// not (yet) on the contact's list. Nothing about the contact changes; the
// message waits until the relay's directory has been asked.
func (v *Vault) HoldAside(peer string, raw []byte) bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil {
		return false
	}
	size := len(raw)
	for _, h := range c.Held {
		size += len(h)
	}
	if len(c.Held) >= maxHeld || (size > maxHeldBytes && len(c.Held) > 0) {
		return false
	}
	c.Held = append(c.Held, append([]byte(nil), raw...))
	return true
}

// TakeHeld returns the messages held for peer and forgets them.
func (v *Vault) TakeHeld(peer string) [][]byte {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil {
		return nil
	}
	held := c.Held
	c.Held = nil
	return held
}

// SetDevices records a contact's device list (version v, linked device keys)
// and which devices can currently be written to. A list older than the one
// on record is ignored. Sessions with devices that are no longer listed are
// dropped. It reports how many linked devices are new, and whether the list
// was taken.
func (v *Vault) SetDevices(peer string, listV uint64, keys [][]byte, reach []string) (added int, ok bool) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil || len(c.Identity) == 0 || listV < c.ListV {
		return 0, false
	}
	for _, k := range keys {
		known := false
		for _, old := range c.Devices {
			known = known || same(old, k)
		}
		if !known {
			added++
		}
	}
	c.ListV, c.Devices = listV, nil
	for _, k := range keys {
		c.Devices = append(c.Devices, append([]byte(nil), k...))
	}
	c.Reach = append([]string(nil), reach...)
	v.dropStaleSessions(peer)
	return added, true
}

// Reach returns the devices of peer that every message has to go to.
func (v *Vault) Reach(peer string) []string {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	if c := v.Contacts[peer]; c != nil {
		return append([]string(nil), c.Reach...)
	}
	return nil
}

// ValidDevice reports whether key is the identity on record for peer or one
// of the devices on their list.
func (v *Vault) ValidDevice(peer string, key []byte) bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return v.validDevice(peer, key)
}

// DropPending forgets a contact's pending identity and the messages held for
// it. It returns how many messages were dropped.
func (v *Vault) DropPending(peer string) int {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil {
		return 0
	}
	n := len(c.Held)
	c.Pending, c.Held, c.Announced = nil, nil, nil
	if len(c.Identity) == 0 && len(v.Messages[peer]) == 0 {
		delete(v.Contacts, peer) // never became a contact
	}
	return n
}

// Announce reports whether the user still has to be told about peer's
// pending identity, and records that they now have been.
func (v *Vault) Announce(peer string) bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil || len(c.Pending) == 0 || same(c.Announced, c.Pending) {
		return false
	}
	c.Announced = append([]byte(nil), c.Pending...)
	return true
}

// AlertDue rate-limits "someone tried to impersonate this contact" notices
// to one per hour and contact.
func (v *Vault) AlertDue(peer string) bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	now := time.Now().Unix()
	if c == nil {
		c = &Contact{FirstSeen: now}
		v.Contacts[peer] = c
	}
	if now-c.LastAlert < 3600 {
		return false
	}
	c.LastAlert = now
	return true
}

// Accept switches a contact to its pending identity (unverified until the
// user verifies it) and returns the messages that were held for it.
func (v *Vault) Accept(peer string) ([][]byte, error) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil || len(c.Pending) == 0 {
		return nil, errors.New("nothing to accept for @" + peer)
	}
	held := c.Held
	c.Identity, c.Verified, c.Pending, c.Held, c.Announced = c.Pending, false, nil, nil, nil
	c.ListV, c.Devices, c.Reach = 0, nil, nil // the new identity's devices are not known yet
	v.dropStaleSessions(peer)
	return held, nil
}

// SetVerified marks whether the user has compared safety numbers with peer.
func (v *Vault) SetVerified(peer string, verified bool) error {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[peer]
	if c == nil || len(c.Identity) == 0 {
		return errors.New("no conversation with @" + peer + " yet — exchange a message first")
	}
	c.Verified = verified
	return nil
}

// ContactInfo is a snapshot for display.
type ContactInfo struct {
	Name       string
	Identity   []byte
	Verified   bool
	Pending    []byte
	Announced  bool // the user has been told about Pending
	Held       int
	Devices    int // devices messages go to (0: not known yet)
	HasSession bool
	MLKEM      uint64 // completed post-quantum ratchet steps
	Frodo      uint64
	Stalled    string
	Messages   int
	LastTS     int64
}

func (v *Vault) contactInfo(name string) ContactInfo {
	info := ContactInfo{Name: name}
	if c := v.Contacts[name]; c != nil {
		info.Identity, info.Verified, info.Pending, info.Held = c.Identity, c.Verified, c.Pending, len(c.Held)
		info.Announced = len(c.Pending) > 0 && same(c.Announced, c.Pending)
	}
	// Several devices, several sessions: report the one that is furthest
	// behind, and any that is stuck.
	for _, k := range v.peerKeys(name) {
		s := v.Sessions[k]
		if s == nil || !v.validDevice(name, s.TheirIdentity) {
			continue
		}
		m, f := s.PQEpochs()
		if !info.HasSession || m+f < info.MLKEM+info.Frodo {
			info.MLKEM, info.Frodo = m, f
		}
		info.HasSession = true
		if st := s.PQStalled(); st != "" {
			info.Stalled = st
		}
	}
	if c := v.Contacts[name]; c != nil {
		info.Devices = len(c.Reach)
	}
	msgs := v.Messages[name]
	info.Messages = len(msgs)
	if len(msgs) > 0 {
		info.LastTS = msgs[len(msgs)-1].TS
	}
	return info
}

// ContactInfo returns what is known about one contact.
func (v *Vault) ContactInfo(name string) (ContactInfo, bool) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	c := v.Contacts[name]
	return v.contactInfo(name), c != nil && len(c.Identity) > 0
}

// ContactList returns all contacts, most recently active first.
func (v *Vault) ContactList() []ContactInfo {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	names := map[string]bool{}
	for n := range v.Contacts {
		names[n] = true
	}
	for n := range v.Messages {
		names[n] = true
	}
	delete(names, v.Username) // one's own other devices are not a conversation
	var out []ContactInfo
	for n := range names {
		out = append(out, v.contactInfo(n))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastTS != out[j].LastTS {
			return out[i].LastTS > out[j].LastTS
		}
		return out[i].Name < out[j].Name
	})
	return out
}
