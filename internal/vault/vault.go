// Package vault is itter's encrypted local state: identity, prekeys, ratchet
// sessions, contacts and message history, in one AES-256-GCM file whose key
// lives in the OS keychain.
//
// Ratchet state is single-use by nature: if two writers (the shell and a
// one-shot `itter dm`, say) each advanced their own copy, message keys would
// be used twice. So every change goes through Update, which takes a file lock,
// picks up changes other processes made, applies the change and writes the
// file before anything derived from it leaves the process.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rrmn/itter-client/internal/pqc"
	"github.com/zalando/go-keyring"
)

const (
	fileName     = "vault.enc"
	usernameFile = "username"
	vaultIDFile  = "vault.id"
	keyFile      = "vault.key" // only with ITTER_KEYFILE=1
	lockFile     = "lock"
	serviceName  = "itter-cli"
)

// KeyFileEnv opts in to keeping the vault key in a file next to the vault,
// for machines without a system keychain (headless Linux, containers). The
// vault is then protected by file permissions only, like an SSH key without
// a passphrase.
const KeyFileEnv = "ITTER_KEYFILE"

// Message delivery states.
const (
	StatusQueued = 0 // encrypted and saved, not yet accepted by the relay
	StatusSent   = 1 // accepted by the relay (or: received)
	StatusFailed = 2 // will not be delivered; the user has been told why
)

type ChatMsg struct {
	ID       string `json:"id"`
	IsOut    bool   `json:"is_out"`
	IsSystem bool   `json:"is_system"`
	Status   int    `json:"status"`
	TS       int64  `json:"ts"`
	Text     string `json:"text"`
}

// QueuedWire holds an ALREADY ENCRYPTED message. Retries re-send bytes as-is;
// re-encrypting on retry would advance the ratchet twice and corrupt the session.
type QueuedWire struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	ToID   string `json:"to_id"` // pqc.IdentityID of the account identity it was encrypted for
	TS     int64  `json:"ts"`
	// Wires holds one encrypted message per device of the recipient.
	Wires map[string][]byte `json:"wires,omitempty"`
	// Init names, per device, the handshake a wire carries (hex ID), so the
	// session can stop attaching it once the relay has taken the message.
	Init map[string]string `json:"init,omitempty"`
	// Payload is the plaintext, kept until the message is out: a device that
	// the recipient links in the meantime needs its own copy.
	Payload []byte `json:"payload,omitempty"`

	Wire []byte `json:"wire,omitempty"` // before devices: the one message
}

// ErrLegacy means the vault predates the post-quantum protocol (v2). It can
// still be burned, but not used.
var ErrLegacy = errors.New("this vault predates the post-quantum upgrade — run `itter burn`, then `itter setup <username>`")

type Vault struct {
	V        int           `json:"v"`
	Username string        `json:"username"`
	Identity *pqc.Identity `json:"identity"`
	// Recovery is the recovery code: the only way to release this identity
	// on the relay without this vault (lost device).
	Recovery []byte `json:"recovery,omitempty"`
	// Registered and KeysPublished make `itter setup` resumable.
	Registered    bool `json:"registered"`
	KeysPublished bool `json:"keys_published"`

	// Identity above is this DEVICE's key. On the account's first device it
	// is also the account identity. On a linked device (Linked) the account
	// identity is someone else's key: Account holds its public half.
	Account []byte `json:"account,omitempty"`
	Linked  bool   `json:"linked,omitempty"`
	// OwnList is the account's signed device list (nil: no linked devices).
	// The first device makes it; linked devices keep a verified copy.
	OwnList *pqc.DeviceList `json:"own_list,omitempty"`
	// ListUnsent is set on the first device while the relay may not have
	// the newest OwnList yet (the upload is retried until it does).
	ListUnsent bool `json:"list_unsent,omitempty"`
	// LinkSecret is the one-time code of a link request that is under way.
	LinkSecret []byte `json:"link_secret,omitempty"`
	// Ignored mirrors itter's ignore list for this account.
	Ignored []string `json:"ignored,omitempty"`
	// RelaySession is this device's session with the relay (a ticket and the
	// key requests are authenticated with), kept so that not every run has
	// to open one. It is worth as much as the device's place on the relay
	// and no more: it reads no message.
	RelaySession []byte `json:"relay_session,omitempty"`

	SPKs         []*pqc.PreKey `json:"spks"`
	OTPKs        []*pqc.PreKey `json:"otpks"`
	NextPreKeyID uint32        `json:"next_prekey_id"`
	LastKeyCheck int64         `json:"last_key_check,omitempty"`

	Contacts map[string]*Contact     `json:"contacts"`
	Sessions map[string]*pqc.Session `json:"sessions"`
	// Previous keeps a few older sessions per contact so crossing handshakes
	// (both sides writing first) and late messages still decrypt.
	Previous map[string][]*pqc.Session `json:"previous,omitempty"`
	// SeenWire remembers recently processed relay messages, so a redelivery
	// (the relay only deletes after an ack) is processed exactly once.
	SeenWire []string `json:"seen_wire,omitempty"`

	Messages map[string][]ChatMsg `json:"messages"`
	// Read is how many lines of each conversation the user has been shown.
	Read   map[string]int `json:"read,omitempty"`
	Outbox []QueuedWire   `json:"outbox"`

	// Mu guards the fields above for readers in this process (the UI).
	Mu sync.Mutex `json:"-"`

	opMu    sync.Mutex // one Update at a time in this process
	dir     string
	account string // OS keychain entry: username@<random vault id>
	key     []byte // cached vault key (one keychain access per process)
	stamp   []byte // nonce of the vault file as last read or written
}

func FilePath(dir string) string     { return filepath.Join(dir, fileName) }
func UsernamePath(dir string) string { return filepath.Join(dir, usernameFile) }

func Exists(dir string) bool {
	_, err := os.Stat(FilePath(dir))
	return err == nil
}

func saveUsername(dir, username string) error {
	return os.WriteFile(UsernamePath(dir), []byte(username), 0o600)
}

// ReadUsername returns the account name this state directory belongs to.
func ReadUsername(dir string) (string, error) {
	b, err := os.ReadFile(UsernamePath(dir))
	if err != nil {
		return "", errors.New("no username file — run `itter setup <username>` first")
	}
	u := strings.TrimSpace(string(b))
	if u == "" {
		return "", errors.New("username file is empty")
	}
	return u, nil
}

// accountFor returns the keychain entry of the vault in dir. The vault.id
// file holds it in full ("name@id"), so it survives a change of the
// account's spelling; older vaults stored only the id.
func accountFor(dir, username string) string {
	b, err := os.ReadFile(filepath.Join(dir, vaultIDFile))
	id := strings.TrimSpace(string(b))
	switch {
	case err != nil || id == "":
		return username // legacy vault
	case strings.Contains(id, "@"):
		return id
	default:
		return username + "@" + id
	}
}

// vaultKey fetches the vault key (once per process): from the key file if
// this vault uses one, otherwise from the OS keychain. With create it is
// generated on first use.
func (v *Vault) vaultKey(create bool) ([]byte, error) {
	if v.key != nil {
		return v.key, nil
	}
	decode := func(keyHex, where string) ([]byte, error) {
		k, err := hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("vault: the key in %s is corrupted", where)
		}
		v.key = k
		return k, nil
	}
	kf := filepath.Join(v.dir, keyFile)
	if b, err := os.ReadFile(kf); err == nil {
		return decode(string(b), kf)
	}
	inFile := os.Getenv(KeyFileEnv) == "1"
	if !inFile {
		if keyHex, err := keyring.Get(serviceName, v.account); err == nil {
			return decode(keyHex, "the system keychain")
		}
	}
	if !create {
		return nil, errors.New("vault: key not found in the system keychain")
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if inFile {
		if err := os.WriteFile(kf, []byte(hex.EncodeToString(k)), 0o600); err != nil {
			return nil, err
		}
	} else if err := keyring.Set(serviceName, v.account, hex.EncodeToString(k)); err != nil {
		return nil, fmt.Errorf("could not store the vault key in the system keychain (%v). On a machine without one (headless Linux, a container) set %s=1 to keep the key in a file instead; the vault is then protected by file permissions only", err, KeyFileEnv)
	}
	v.key = k
	return k, nil
}

// Create makes the vault of an account's first device: a fresh identity and
// a recovery code.
func Create(dir, username string) (*Vault, error) { return create(dir, username, false) }

// CreateLinked makes the vault of a device that will be linked to an existing
// account: a fresh device key, no recovery code (that belongs to the account
// identity, which stays on the first device).
func CreateLinked(dir, username string) (*Vault, error) { return create(dir, username, true) }

func create(dir, username string, linked bool) (*Vault, error) {
	if Exists(dir) {
		return nil, errors.New("vault already exists")
	}
	id, err := pqc.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	rid := make([]byte, 8)
	recovery := make([]byte, 32)
	if _, err := rand.Read(rid); err != nil {
		return nil, err
	}
	if _, err := rand.Read(recovery); err != nil {
		return nil, err
	}
	account := username + "@" + hex.EncodeToString(rid)
	if err := os.WriteFile(filepath.Join(dir, vaultIDFile), []byte(account), 0o600); err != nil {
		return nil, err
	}
	v := &Vault{
		V:            pqc.ProtocolVersion,
		Username:     username,
		Identity:     id,
		Recovery:     recovery,
		Linked:       linked,
		NextPreKeyID: 1,
		dir:          dir,
		account:      account,
	}
	if linked {
		v.Recovery = nil
	}
	v.initMaps()
	if _, err := v.vaultKey(true); err != nil {
		return nil, err
	}
	if err := saveUsername(dir, username); err != nil {
		return nil, err
	}
	return v, v.Update(func() error { return nil })
}

func (v *Vault) initMaps() {
	if v.Contacts == nil {
		v.Contacts = map[string]*Contact{}
	}
	if v.Sessions == nil {
		v.Sessions = map[string]*pqc.Session{}
	}
	if v.Previous == nil {
		v.Previous = map[string][]*pqc.Session{}
	}
	if v.Messages == nil {
		v.Messages = map[string][]ChatMsg{}
	}
	if v.Read == nil {
		v.Read = map[string]int{}
	}
}

// Open loads the vault in dir. For a pre-v2 vault it returns the vault
// together with ErrLegacy, so it can still be burned.
func Open(dir string) (*Vault, error) {
	if !Exists(dir) {
		return nil, fmt.Errorf("this device is not set up for DMs yet (nothing in %s) — run `itter` to set it up", dir)
	}
	username, err := ReadUsername(dir)
	if err != nil {
		return nil, err
	}
	v := &Vault{dir: dir, account: accountFor(dir, username)}
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := v.load(); err != nil {
		return nil, err
	}
	if !v.Identity.Valid() {
		if v.Username == "" {
			v.Username = username
		}
		return v, ErrLegacy
	}
	return v, nil
}

// load reads and decrypts the vault file into v. Callers hold the file lock.
func (v *Vault) load() error {
	path := FilePath(v.dir)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(raw) < 12+16 {
		return errors.New("vault: file corrupted")
	}
	key, err := v.vaultKey(false)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	pt, err := g.Open(nil, raw[:12], raw[12:], nil)
	if err != nil {
		return errors.New("vault: decryption failed (wrong keychain entry or corrupted file)")
	}
	var nv Vault
	if err := json.Unmarshal(pt, &nv); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	nv.initMaps()
	nv.migrate()

	v.Mu.Lock()
	defer v.Mu.Unlock()
	v.V, v.Username, v.Identity, v.Recovery = nv.V, nv.Username, nv.Identity, nv.Recovery
	v.Registered, v.KeysPublished = nv.Registered, nv.KeysPublished
	v.Account, v.Linked, v.OwnList, v.LinkSecret, v.Ignored = nv.Account, nv.Linked, nv.OwnList, nv.LinkSecret, nv.Ignored
	v.ListUnsent, v.RelaySession = nv.ListUnsent, nv.RelaySession
	v.SPKs, v.OTPKs, v.NextPreKeyID, v.LastKeyCheck = nv.SPKs, nv.OTPKs, nv.NextPreKeyID, nv.LastKeyCheck
	v.Contacts, v.Sessions, v.Previous = nv.Contacts, nv.Sessions, nv.Previous
	v.SeenWire = nv.SeenWire
	v.Messages, v.Read, v.Outbox = nv.Messages, nv.Read, nv.Outbox
	v.stamp = append([]byte(nil), raw[:12]...)
	return nil
}

// migrate tidies state written by earlier builds.
func (v *Vault) migrate() {
	// Sessions from the pre-quantum protocol cannot be continued.
	for peer, s := range v.Sessions {
		if !s.Valid() {
			delete(v.Sessions, peer)
		}
	}
	for peer, list := range v.Previous {
		var kept []*pqc.Session
		for _, s := range list {
			if s.Valid() {
				kept = append(kept, s)
			}
		}
		v.Previous[peer] = kept
	}
	// Trust used to be a flag on the session; it belongs to the contact.
	for peer, s := range v.Sessions {
		if !strings.Contains(peer, "/") && v.Contacts[peer] == nil && len(s.TheirIdentity) > 0 {
			v.Contacts[peer] = &Contact{Identity: s.TheirIdentity, Verified: s.Trusted, FirstSeen: time.Now().Unix()}
		}
	}
	// Sessions used to be per contact; they are per device of a contact.
	for peer, s := range v.Sessions {
		if !strings.Contains(peer, "/") {
			delete(v.Sessions, peer)
			v.Sessions[skey(peer, devID(s.TheirIdentity))] = s
		}
	}
	for peer, list := range v.Previous {
		if !strings.Contains(peer, "/") {
			delete(v.Previous, peer)
			for _, s := range list {
				k := skey(peer, devID(s.TheirIdentity))
				v.Previous[k] = append(v.Previous[k], s)
			}
		}
	}
	for peer, c := range v.Contacts {
		if len(c.Reach) == 0 && len(c.Identity) > 0 && peer != v.Username {
			c.Reach = []string{devID(c.Identity)}
		}
	}
	for i := range v.Outbox {
		if q := &v.Outbox[i]; len(q.Wires) == 0 && len(q.Wire) > 0 {
			q.Wires, q.Wire = map[string][]byte{q.ToID: q.Wire}, nil
		}
	}
}

// save encrypts and writes the vault. Callers hold the file lock.
func (v *Vault) save() error {
	v.Mu.Lock()
	pt, err := json.Marshal(v)
	v.Mu.Unlock()
	if err != nil {
		return err
	}
	key, err := v.vaultKey(true)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	out := g.Seal(nonce, nonce, pt, nil)

	path := FilePath(v.dir)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		return err
	}
	// Ratchet state must really be on disk before a message is sent.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	v.Mu.Lock()
	v.stamp = nonce
	v.Mu.Unlock()
	return nil
}

// changedOnDisk reports whether another process wrote the vault since we
// last read or wrote it. Every save uses a fresh random nonce, which makes
// the first bytes of the file an exact change marker (file times are too
// coarse for this: two saves can share a timestamp).
func (v *Vault) changedOnDisk() bool {
	f, err := os.Open(FilePath(v.dir))
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 12)
	if _, err := io.ReadFull(f, head); err != nil {
		return true
	}
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return !bytes.Equal(head, v.stamp)
}

// Update is the only way to change the vault. It takes the cross-process
// lock, reloads the file if another process changed it, runs fn, and writes
// the result to disk. Whatever fn changed is saved even if fn returns an
// error; a failed save is returned as the error.
//
// fn must not do network I/O (it would block other itter processes), and it
// must look sessions and contacts up afresh: objects obtained before Update
// may have been replaced by the reload.
func (v *Vault) Update(fn func() error) error {
	v.opMu.Lock()
	defer v.opMu.Unlock()
	unlock, err := lockDir(v.dir)
	if err != nil {
		return err
	}
	defer unlock()
	if Exists(v.dir) && v.changedOnDisk() {
		if err := v.load(); err != nil {
			return err
		}
	}
	ferr := fn()
	if err := v.save(); err != nil {
		return fmt.Errorf("could not save the vault (%w) — nothing was sent", err)
	}
	return ferr
}

// Refresh picks up changes made by other itter processes.
func (v *Vault) Refresh() error {
	v.opMu.Lock()
	defer v.opMu.Unlock()
	if !v.changedOnDisk() {
		return nil
	}
	unlock, err := lockDir(v.dir)
	if err != nil {
		return err
	}
	defer unlock()
	return v.load()
}

// Burn shreds the vault file and removes its keychain entry. Deleting the
// key is what makes the data unrecoverable; overwriting is best effort.
func (v *Vault) Burn() error {
	v.opMu.Lock()
	defer v.opMu.Unlock()
	unlock, err := lockDir(v.dir)
	if err == nil {
		defer unlock()
	}
	_ = keyring.Delete(serviceName, v.account)
	for _, name := range []string{fileName, fileName + ".tmp", keyFile, usernameFile, vaultIDFile} {
		path := filepath.Join(v.dir, name)
		if info, err := os.Stat(path); err == nil {
			junk := make([]byte, info.Size())
			_, _ = rand.Read(junk)
			_ = os.WriteFile(path, junk, 0o600)
			_ = os.Remove(path)
		}
	}
	_ = os.Remove(filepath.Join(v.dir, lockFile))
	return nil
}

// --- account ---

// Me returns the account name and identity.
func (v *Vault) Me() (string, *pqc.Identity) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return v.Username, v.Identity
}

// Dir returns the state directory.
func (v *Vault) Dir() string { return v.dir }

// AccountIdentity returns the account identity: the key contacts know this
// account by. On the first device that is the device's own key.
func (v *Vault) AccountIdentity() []byte {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	if v.Linked {
		return v.Account
	}
	return v.Identity.Pub.Encode()
}

// IsLinked reports whether this is a linked device (not the account's first).
func (v *Vault) IsLinked() bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return v.Linked
}

// DeviceID returns this device's ID.
func (v *Vault) DeviceID() string {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return devID(v.Identity.Pub.Encode())
}

// LinkCode returns the one-time code of the link request this device is
// waiting on, creating it on first use. Call inside Update.
func (v *Vault) LinkCode() ([]byte, error) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	if len(v.LinkSecret) != pqc.LinkSecretSize {
		v.LinkSecret = make([]byte, pqc.LinkSecretSize)
		if _, err := rand.Read(v.LinkSecret); err != nil {
			return nil, err
		}
	}
	return append([]byte(nil), v.LinkSecret...), nil
}

// OwnDevices returns the account's signed device list (nil: none linked).
func (v *Vault) OwnDevices() *pqc.DeviceList {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return v.OwnList
}

// SetOwnDevices records the account's device list and which of the devices
// can be written to. Conversations between one's own devices use the same
// machinery as those with a contact, under one's own name. On a linked device
// account is the account identity it was linked to. Call inside Update.
func (v *Vault) SetOwnDevices(account []byte, l *pqc.DeviceList, reach []string) {
	v.Mu.Lock()
	if v.Linked {
		v.Account = append([]byte(nil), account...)
		v.LinkSecret = nil
	}
	if l.Version() >= v.OwnList.Version() {
		v.OwnList = l
	}
	c := v.Contacts[v.Username]
	if c == nil {
		c = &Contact{FirstSeen: time.Now().Unix(), Verified: true}
		v.Contacts[v.Username] = c
	}
	c.Identity = append([]byte(nil), account...)
	list := v.OwnList
	me := v.Username
	v.Mu.Unlock()
	var keys [][]byte
	if list != nil {
		keys = list.Keys
	}
	v.SetDevices(me, list.Version(), keys, reach)
}

// ListNeedsUpload reports whether the first device still has to publish its
// newest device list; SetListUploaded records the outcome. Call the setter
// inside Update.
func (v *Vault) ListNeedsUpload() bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return v.ListUnsent && v.OwnList != nil && !v.Linked
}

func (v *Vault) SetListUploaded(done bool) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	v.ListUnsent = !done
}

// IgnoreList returns who this account ignores, as last heard from the relay.
func (v *Vault) IgnoreList() []string {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return append([]string(nil), v.Ignored...)
}

// SetIgnoreList records the account's ignore list. Call inside Update.
func (v *Vault) SetIgnoreList(names []string) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	v.Ignored = append([]string(nil), names...)
}

// SetUsername records how itter spells the account name. Call inside Update.
func (v *Vault) SetUsername(name string) error {
	v.Mu.Lock()
	v.Username = name
	v.Mu.Unlock()
	return saveUsername(v.dir, name)
}

// RelaySessionBlob returns the stored relay session (see relay.Session), nil
// if there is none.
func (v *Vault) RelaySessionBlob() []byte {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return append([]byte(nil), v.RelaySession...)
}

// SetRelaySessionBlob stores the relay session, or forgets it (nil). Call
// inside Update.
func (v *Vault) SetRelaySessionBlob(b []byte) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	v.RelaySession = append([]byte(nil), b...)
}

// SetupState reports how far `itter setup` got.
func (v *Vault) SetupState() (registered, keysPublished bool) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return v.Registered, v.KeysPublished
}

// SetSetupState records setup progress. Call inside Update.
func (v *Vault) SetSetupState(registered, keysPublished bool) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	v.Registered, v.KeysPublished = registered, keysPublished
}

// RecoveryCode returns the recovery code, creating one if the vault has none
// yet (vaults from the first v2 build). Call inside Update.
func (v *Vault) RecoveryCode() ([]byte, error) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	if v.Linked {
		return nil, errors.New("the recovery code belongs to the account's first device")
	}
	if len(v.Recovery) != 32 {
		code := make([]byte, 32)
		if _, err := rand.Read(code); err != nil {
			return nil, err
		}
		v.Recovery = code
	}
	return append([]byte(nil), v.Recovery...), nil
}

// --- messages ---

func (v *Vault) AddMessage(contact string, msg ChatMsg) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	v.Messages[contact] = append(v.Messages[contact], msg)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// AddSystem records a notice in the conversation with contact.
func (v *Vault) AddSystem(contact, text string) {
	v.AddMessage(contact, ChatMsg{ID: newID(), IsSystem: true, Status: StatusSent, TS: time.Now().Unix(), Text: text})
}

// IncomingTS turns a sender-supplied timestamp into one that is safe to sort
// by: never in the future and never before the previous message of that
// conversation, so a peer cannot slip messages into old history.
func (v *Vault) IncomingTS(contact string, senderTS int64) int64 {
	now := time.Now().Unix()
	v.Mu.Lock()
	defer v.Mu.Unlock()
	ts := senderTS
	if ts > now {
		ts = now
	}
	if msgs := v.Messages[contact]; len(msgs) > 0 && ts < msgs[len(msgs)-1].TS {
		ts = msgs[len(msgs)-1].TS
	}
	return ts
}

func (v *Vault) SetStatus(contact, msgID string, status int) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	for i := range v.Messages[contact] {
		if v.Messages[contact][i].ID == msgID {
			v.Messages[contact][i].Status = status
		}
	}
}

func (v *Vault) GetMessages(contact string) []ChatMsg {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return append([]ChatMsg(nil), v.Messages[contact]...)
}

func (v *Vault) GetAllMessages() map[string][]ChatMsg {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	out := map[string][]ChatMsg{}
	for k, msgs := range v.Messages {
		out[k] = append([]ChatMsg(nil), msgs...)
	}
	return out
}

// ReadCounts returns, per conversation, how many lines the user has seen.
func (v *Vault) ReadCounts() map[string]int {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	out := make(map[string]int, len(v.Read))
	for k, n := range v.Read {
		out[k] = n
	}
	return out
}

// MarkRead records that the user has seen the first counts[c] lines of each
// conversation c. It never moves a marker backwards. Call inside Update.
func (v *Vault) MarkRead(counts map[string]int) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	for c, n := range counts {
		if n > len(v.Messages[c]) {
			n = len(v.Messages[c])
		}
		if n > v.Read[c] {
			v.Read[c] = n
		}
	}
}

// --- outbox ---

// QueueBatch queues one already encrypted message per device of target.
func (v *Vault) QueueBatch(q QueuedWire) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	q.TS = time.Now().Unix()
	v.Outbox = append(v.Outbox, q)
}

// EditOutbox changes a queued message in place (its set of devices changed).
func (v *Vault) EditOutbox(msgID string, fn func(q *QueuedWire)) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	for i := range v.Outbox {
		if v.Outbox[i].ID == msgID {
			fn(&v.Outbox[i])
		}
	}
}

func (v *Vault) OutboxSnapshot() []QueuedWire {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return append([]QueuedWire(nil), v.Outbox...)
}

func (v *Vault) RemoveOutbox(msgID string) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	kept := v.Outbox[:0:0]
	for _, q := range v.Outbox {
		if q.ID != msgID {
			kept = append(kept, q)
		}
	}
	v.Outbox = kept
}

// FailOutboxFor drops everything queued for target and marks those messages
// as not delivered. It returns how many there were.
func (v *Vault) FailOutboxFor(target string) int {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	kept := v.Outbox[:0:0]
	n := 0
	for _, q := range v.Outbox {
		if q.Target != target {
			kept = append(kept, q)
			continue
		}
		n++
		for i := range v.Messages[target] {
			if v.Messages[target][i].ID == q.ID {
				v.Messages[target][i].Status = StatusFailed
			}
		}
	}
	v.Outbox = kept
	return n
}

// --- wire dedupe ---

const maxSeenWire = 2000

// FirstTime reports whether a relay message (identified by a digest of its
// bytes) is new, and remembers it.
func (v *Vault) FirstTime(digest string) bool {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	for _, d := range v.SeenWire {
		if d == digest {
			return false
		}
	}
	v.SeenWire = append(v.SeenWire, digest)
	if len(v.SeenWire) > maxSeenWire {
		v.SeenWire = append([]string(nil), v.SeenWire[len(v.SeenWire)-maxSeenWire:]...)
	}
	return true
}

// --- prekeys ---

const (
	keepSPKs  = 3   // previous signed prekeys kept for handshakes in flight
	keepOTPKs = 200 // unused one-time prekeys kept locally
)

// AddPreKeys stores freshly generated prekeys. This must be saved BEFORE the
// public halves are uploaded, or a crash in between would leave the relay
// handing out prekeys nobody can answer.
func (v *Vault) AddPreKeys(spk *pqc.PreKey, otpks []*pqc.PreKey) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	if spk != nil {
		v.SPKs = append(v.SPKs, spk)
		if len(v.SPKs) > keepSPKs {
			v.SPKs = append([]*pqc.PreKey(nil), v.SPKs[len(v.SPKs)-keepSPKs:]...)
		}
	}
	v.OTPKs = append(v.OTPKs, otpks...)
	if len(v.OTPKs) > keepOTPKs {
		v.OTPKs = append([]*pqc.PreKey(nil), v.OTPKs[len(v.OTPKs)-keepOTPKs:]...)
	}
}

// ReservePreKeyIDs hands out n unused prekey ids. Call inside Update.
func (v *Vault) ReservePreKeyIDs(n int) uint32 {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	if v.NextPreKeyID == 0 {
		v.NextPreKeyID = 1
	}
	first := v.NextPreKeyID
	v.NextPreKeyID += uint32(n)
	return first
}

// KeyCheck returns when prekeys were last checked against the relay.
func (v *Vault) KeyCheck() int64 {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return v.LastKeyCheck
}

// SetKeyCheck records a prekey check. Call inside Update.
func (v *Vault) SetKeyCheck(ts int64) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	v.LastKeyCheck = ts
}

// LatestSPK returns the current signed prekey (nil if none).
func (v *Vault) LatestSPK() *pqc.PreKey {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	if len(v.SPKs) == 0 {
		return nil
	}
	return v.SPKs[len(v.SPKs)-1]
}

func (v *Vault) FindSPK(id uint32) *pqc.PreKey {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	for _, k := range v.SPKs {
		if k.ID == id {
			return k
		}
	}
	return nil
}

func (v *Vault) FindOTPK(id uint32) *pqc.PreKey {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	for _, k := range v.OTPKs {
		if k.ID == id {
			return k
		}
	}
	return nil
}

func (v *Vault) ConsumeOTPK(id uint32) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	for i, k := range v.OTPKs {
		if k.ID == id {
			v.OTPKs = append(v.OTPKs[:i:i], v.OTPKs[i+1:]...)
			return
		}
	}
}
