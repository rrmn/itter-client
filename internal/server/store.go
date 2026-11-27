package server

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"itter-cli/internal/pqc"
)

var errNotFound = errors.New("not found")

// User is an itter account. Name is spelled the way itter stores it; lookups
// ignore case, like itter's own uniqueness rule.
type User struct {
	ID   string
	Name string
}

// IdentityRecord is a DM identity bound to an account.
type IdentityRecord struct {
	Identity    []byte // pqc.IdentityKey encoding
	ID          string // pqc.IdentityID(Identity)
	RecoveryKey []byte
	// List is the account's signed device list (a pqc.DeviceList as JSON),
	// nil while the account never had a linked device. ListV is its version.
	List  []byte
	ListV uint64
}

// Device is one device of an account. The first device's key is the account
// identity itself.
type Device struct {
	ID      string // pqc.IdentityID(Key)
	Key     []byte
	Primary bool
}

// SPK is a device's signed prekey.
type SPK struct {
	Key *pqc.PreKeyPublic
	Sig []byte
}

// Link is a new device's request to be linked, and the answer once the
// first device has given one.
type Link struct {
	ID        string
	DeviceKey []byte
	Tag       []byte
	Result    []byte
}

// linkTTL is how long a link request waits for its answer.
const linkTTL = 15 * time.Minute

// StoredMsg is a message waiting in an inbox.
type StoredMsg struct {
	ID      int64
	Payload []byte // the pqc.WireMsg as JSON
}

// Store is the relay's persistence. SupabaseStore is for production;
// MemStore runs a self-contained relay for local testing.
type Store interface {
	User(username string) (User, error)      // errNotFound if there is no such account
	SSHKeys(userID string) ([]string, error) // authorized_keys lines

	Identity(userID string) (*IdentityRecord, error) // nil, nil if none
	// CreateIdentity stores the identity, and with it the account's first
	// device, unless the account already has one (first writer wins); it
	// reports whether it was stored.
	CreateIdentity(u User, rec *IdentityRecord) (bool, error)
	// DeleteIdentity removes the identity with all its devices, their
	// prekeys and waiting messages.
	DeleteIdentity(userID string) error

	// Devices lists the account's devices, the first device first.
	Devices(userID string) ([]Device, error)
	// DeviceIDs is the cheap form of Devices: the account identity's ID
	// ("" if there is none) and the IDs of all devices.
	DeviceIDs(userID string) (identityID string, ids []string, err error)
	// SetDeviceList replaces the linked devices with those of a newer signed
	// list. Devices that are no longer listed lose their prekeys and waiting
	// messages. It reports false if v is not newer than what is stored.
	SetDeviceList(userID string, v uint64, list []byte, linked []Device) (bool, error)
	// ClearDevice removes a device's prekeys and waiting messages. It stays
	// listed, but nothing is sent to it any more.
	ClearDevice(userID, deviceID string) error

	PutPreKeys(userID, deviceID string, spk *pqc.PreKeyPublic, spkSig []byte, otpks []*pqc.PreKeyPublic) error
	// SignedPreKeys returns the signed prekey of every device that has one:
	// those are the devices that can be written to.
	SignedPreKeys(userID string) (map[string]SPK, error)
	ClaimOTPK(userID, deviceID string) (*pqc.PreKeyPublic, error) // nil, nil if none left
	CountOTPKs(userID, deviceID string) (int, error)

	// PutMessages queues one message per device. A device that already has
	// limit messages from that sender waiting is left out: a device that is
	// away must not keep the account's other devices from getting theirs. It
	// reports false, having stored nothing, if no device had room.
	PutMessages(toUserID, from string, msgs map[string][]byte, limit int) (bool, error)
	Senders(userID, deviceID string) (map[string]int, error)
	Messages(userID, deviceID, from string, limit int) ([]StoredMsg, error) // oldest first, not deleted
	Ack(userID, deviceID string, ids []int64) error                         // delete delivered messages

	// PutLink files a link request unless max are already waiting.
	PutLink(userID string, l *Link, max int) (bool, error)
	Link(userID, linkID string) (*Link, error) // nil, nil if none (or expired)
	SetLinkResult(userID, linkID string, result []byte) error

	// The ignore list is itter's own (ignored_users): what a user ignores on
	// itter, they do not get DMs from either.
	Ignores(userID, otherID string) (bool, error)
	// SetIgnore changes the list; ignoring also drops what the other
	// account has waiting for the user.
	SetIgnore(u, other User, ignore bool) error
	Ignored(userID string) ([]string, error) // usernames
}

// MemStore keeps everything in memory.
type MemStore struct {
	mu      sync.Mutex
	users   map[string]User     // lower-case name -> user
	keys    map[string][]string // user id -> ssh keys
	ids     map[string]*IdentityRecord
	devs    map[string][]Device // user id -> devices, first device first
	spk     map[string]SPK      // user id + "/" + device id -> signed prekey
	otpks   map[string][]*pqc.PreKeyPublic
	inbox   map[string][]memMsg
	links   map[string]map[string]*memLink
	ignores map[string]map[string]bool // user id -> ignored user id
	nextID  int64
}

type memMsg struct {
	id      int64
	from    string
	payload []byte
}

type memLink struct {
	Link
	created time.Time
}

func NewMemStore() *MemStore {
	return &MemStore{users: map[string]User{}, keys: map[string][]string{}, ids: map[string]*IdentityRecord{},
		devs: map[string][]Device{}, spk: map[string]SPK{}, otpks: map[string][]*pqc.PreKeyPublic{},
		inbox: map[string][]memMsg{}, links: map[string]map[string]*memLink{}, ignores: map[string]map[string]bool{}}
}

func dk(userID, deviceID string) string { return userID + "/" + deviceID }

// AddUser registers an itter account with its SSH public keys.
func (m *MemStore) AddUser(username string, sshKeys ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[strings.ToLower(username)]
	if !ok {
		u = User{ID: "mem-" + strings.ToLower(username), Name: username}
		m.users[strings.ToLower(username)] = u
	}
	m.keys[u.ID] = append(m.keys[u.ID], sshKeys...)
}

func (m *MemStore) User(username string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[strings.ToLower(username)]; ok {
		return u, nil
	}
	return User{}, errNotFound
}

func (m *MemStore) SSHKeys(id string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.keys[id]...), nil
}

func (m *MemStore) Identity(id string) (*IdentityRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec := m.ids[id]; rec != nil {
		cp := *rec
		return &cp, nil
	}
	return nil, nil
}

func (m *MemStore) CreateIdentity(u User, rec *IdentityRecord) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ids[u.ID] != nil {
		return false, nil
	}
	cp := *rec
	m.ids[u.ID] = &cp
	m.devs[u.ID] = []Device{{ID: rec.ID, Key: rec.Identity, Primary: true}}
	return true, nil
}

// dropDevice forgets a device's prekeys and waiting messages. Callers hold mu.
func (m *MemStore) dropDevice(userID, deviceID string) {
	delete(m.spk, dk(userID, deviceID))
	delete(m.otpks, dk(userID, deviceID))
	delete(m.inbox, dk(userID, deviceID))
}

func (m *MemStore) DeleteIdentity(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.devs[id] {
		m.dropDevice(id, d.ID)
	}
	delete(m.ids, id)
	delete(m.devs, id)
	delete(m.links, id)
	return nil
}

func (m *MemStore) Devices(id string) ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Device(nil), m.devs[id]...), nil
}

func (m *MemStore) DeviceIDs(id string) (string, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.ids[id]
	if rec == nil {
		return "", nil, nil
	}
	var ids []string
	for _, d := range m.devs[id] {
		ids = append(ids, d.ID)
	}
	return rec.ID, ids, nil
}

func (m *MemStore) SetDeviceList(id string, v uint64, list []byte, linked []Device) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.ids[id]
	if rec == nil || v <= rec.ListV {
		return false, nil
	}
	keep := map[string]bool{rec.ID: true}
	devs := []Device{{ID: rec.ID, Key: rec.Identity, Primary: true}}
	for _, d := range linked {
		keep[d.ID] = true
		devs = append(devs, Device{ID: d.ID, Key: d.Key})
	}
	for _, d := range m.devs[id] {
		if !keep[d.ID] {
			m.dropDevice(id, d.ID)
		}
	}
	m.devs[id] = devs
	rec.List, rec.ListV = append([]byte(nil), list...), v
	return true, nil
}

func (m *MemStore) ClearDevice(id, dev string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropDevice(id, dev)
	return nil
}

func (m *MemStore) hasDevice(id, dev string) bool {
	for _, d := range m.devs[id] {
		if d.ID == dev {
			return true
		}
	}
	return false
}

func (m *MemStore) PutPreKeys(id, dev string, spk *pqc.PreKeyPublic, sig []byte, otpks []*pqc.PreKeyPublic) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasDevice(id, dev) {
		return errNotFound
	}
	k := dk(id, dev)
	m.spk[k] = SPK{Key: spk, Sig: sig}
	have := map[uint32]bool{}
	for _, o := range m.otpks[k] {
		have[o.ID] = true
	}
	for _, o := range otpks {
		if !have[o.ID] { // never re-issue a one-time key
			m.otpks[k] = append(m.otpks[k], o)
			have[o.ID] = true
		}
	}
	return nil
}

func (m *MemStore) SignedPreKeys(id string) (map[string]SPK, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]SPK{}
	for _, d := range m.devs[id] {
		if s, ok := m.spk[dk(id, d.ID)]; ok {
			out[d.ID] = s
		}
	}
	return out, nil
}

func (m *MemStore) ClaimOTPK(id, dev string) (*pqc.PreKeyPublic, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := dk(id, dev)
	if len(m.otpks[k]) == 0 {
		return nil, nil
	}
	o := m.otpks[k][0]
	m.otpks[k] = m.otpks[k][1:]
	return o, nil
}

func (m *MemStore) CountOTPKs(id, dev string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.otpks[dk(id, dev)]), nil
}

func (m *MemStore) PutMessages(to, from string, msgs map[string][]byte, limit int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var devs []string
	for dev := range msgs {
		if !m.hasDevice(to, dev) {
			return false, errNotFound
		}
		n := 0
		for _, msg := range m.inbox[dk(to, dev)] {
			if msg.from == from {
				n++
			}
		}
		if n < limit {
			devs = append(devs, dev)
		}
	}
	sort.Strings(devs)
	for _, dev := range devs {
		m.nextID++
		m.inbox[dk(to, dev)] = append(m.inbox[dk(to, dev)], memMsg{m.nextID, from, append([]byte(nil), msgs[dev]...)})
	}
	return len(devs) > 0, nil
}

func (m *MemStore) Senders(id, dev string) (map[string]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, msg := range m.inbox[dk(id, dev)] {
		out[msg.from]++
	}
	return out, nil
}

func (m *MemStore) Messages(id, dev, from string, limit int) ([]StoredMsg, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StoredMsg
	for _, msg := range m.inbox[dk(id, dev)] {
		if msg.from == from && len(out) < limit {
			out = append(out, StoredMsg{msg.id, msg.payload})
		}
	}
	return out, nil
}

func (m *MemStore) Ack(id, dev string, ids []int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	drop := map[int64]bool{}
	for _, i := range ids {
		drop[i] = true
	}
	var kept []memMsg
	for _, msg := range m.inbox[dk(id, dev)] {
		if !drop[msg.id] {
			kept = append(kept, msg)
		}
	}
	m.inbox[dk(id, dev)] = kept
	return nil
}

func (m *MemStore) PutLink(id string, l *Link, max int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.links[id] == nil {
		m.links[id] = map[string]*memLink{}
	}
	for k, old := range m.links[id] {
		if time.Since(old.created) > linkTTL {
			delete(m.links[id], k)
		}
	}
	if _, again := m.links[id][l.ID]; !again && len(m.links[id]) >= max {
		return false, nil
	}
	m.links[id][l.ID] = &memLink{Link: *l, created: time.Now()}
	return true, nil
}

func (m *MemStore) Link(id, linkID string) (*Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.links[id][linkID]
	if l == nil || time.Since(l.created) > linkTTL {
		return nil, nil
	}
	cp := l.Link
	return &cp, nil
}

func (m *MemStore) SetLinkResult(id, linkID string, result []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.links[id][linkID]
	if l == nil {
		return errNotFound
	}
	l.Result = append([]byte(nil), result...)
	return nil
}

func (m *MemStore) Ignores(id, other string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ignores[id][other], nil
}

func (m *MemStore) SetIgnore(u, other User, ignore bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !ignore {
		delete(m.ignores[u.ID], other.ID)
		return nil
	}
	if m.ignores[u.ID] == nil {
		m.ignores[u.ID] = map[string]bool{}
	}
	m.ignores[u.ID][other.ID] = true
	for _, d := range m.devs[u.ID] {
		var kept []memMsg
		for _, msg := range m.inbox[dk(u.ID, d.ID)] {
			if msg.from != other.Name {
				kept = append(kept, msg)
			}
		}
		m.inbox[dk(u.ID, d.ID)] = kept
	}
	return nil
}

func (m *MemStore) Ignored(id string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, u := range m.users {
		if m.ignores[id][u.ID] {
			out = append(out, u.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Usernames lists registered users (for diagnostics).
func (m *MemStore) Usernames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, u := range m.users {
		out = append(out, u.Name)
	}
	sort.Strings(out)
	return out
}

// Pending reports how many messages wait for a user on all devices (for tests).
func (m *MemStore) Pending(username string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[strings.ToLower(username)]
	if !ok {
		return 0
	}
	n := 0
	for _, d := range m.devs[u.ID] {
		n += len(m.inbox[dk(u.ID, d.ID)])
	}
	return n
}
