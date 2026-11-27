package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rrmn/itter-client/internal/api"
	"github.com/rrmn/itter-client/internal/pqc"
	"github.com/rrmn/itter-client/internal/relay"
	"github.com/rrmn/itter-client/internal/vault"
)

// app is everything a command needs: the vault and the relay.
//
// The rule that keeps the ratchets safe: state is changed inside v.Update
// (locked across processes, written to disk before it returns) and only
// then does anything derived from it go to the network.
type app struct {
	v  *vault.Vault
	rc *relay.Client

	flushMu sync.Mutex // one outbox flush at a time
	// offline is set by the shell's poll loop while the relay cannot be
	// reached. Sends then go straight to the outbox instead of each waiting
	// for a connection attempt to time out; the loop delivers them later.
	offline atomic.Bool
}

var errOffline = errors.New("no connection")

// linkedDevice is whether the vault this process opened belongs to a linked
// device (and not the account's first one). Error messages depend on it.
var linkedDevice atomic.Bool

// auth identifies this device to the relay.
func (a *app) auth() relay.Auth {
	name, id := a.v.Me()
	return relay.Auth{Username: name, ID: id}
}

// vaultSessions keeps the device's relay session in its vault.
type vaultSessions struct{ v *vault.Vault }

func (s vaultSessions) LoadSession() *relay.Session {
	var sess relay.Session
	if b := s.v.RelaySessionBlob(); len(b) == 0 || json.Unmarshal(b, &sess) != nil {
		return nil
	}
	return &sess
}

func (s vaultSessions) SaveSession(sess *relay.Session) error {
	var b []byte
	if sess != nil {
		b, _ = json.Marshal(sess)
	}
	return s.v.Update(func() error { s.v.SetRelaySessionBlob(b); return nil })
}

// newApp ties a vault to a relay: the relay client keeps its session there.
// v may be nil while a device is being set up; setVault comes later then.
func newApp(v *vault.Vault, rc *relay.Client) *app {
	a := &app{rc: rc}
	if v != nil {
		a.setVault(v)
	}
	return a
}

func (a *app) setVault(v *vault.Vault) {
	a.v = v
	a.rc.Sessions = vaultSessions{v}
}

// userErr is an error already phrased for the user.
type userErr struct{ msg string }

func (e *userErr) Error() string { return e.msg }

func userErrf(format string, args ...any) error { return &userErr{fmt.Sprintf(format, args...)} }

// explain turns any error into one line a user can act on.
func explain(err error) string {
	var ue *userErr
	if errors.As(err, &ue) {
		return ue.msg
	}
	var hk *relay.HostKeyError
	if errors.As(err, &hk) {
		return fmt.Sprintf("itter's server at %s shows a different SSH host key (%s) than the one on record in %s. That happens when a server is moved or reinstalled, and it is also what someone in between looks like. Nothing was sent. If itter announced a new key, remove that line from the file and try again", hk.Addr, hk.Got, tilde(hk.Record))
	}
	var ge *relay.GateError
	if errors.As(err, &ge) {
		return ge.Reason
	}
	if errors.Is(err, relay.ErrSessionAnswer) {
		return "the relay's answer could not be used: it was damaged on the way, or it did not come from the relay. Nothing was sent — try again"
	}
	var he *relay.HTTPError
	if !errors.As(err, &he) {
		return fmt.Sprintf("can't reach the relay (%v)", err)
	}
	switch {
	case he.Status == http.StatusUnauthorized && he.Body == api.ErrClockSkew:
		if he.ServerTime != 0 {
			if off := time.Since(time.Unix(he.ServerTime, 0)); off > time.Minute || off < -time.Minute {
				return fmt.Sprintf("your clock is off by about %s — fix the system time and try again", off.Abs().Round(time.Minute))
			}
		}
		return "the relay rejected the request because your clock is off — fix the system time and try again"
	case he.Status == http.StatusUnauthorized && he.Body == api.ErrSessionGone:
		// The client already tried once more with a new session.
		return "the relay keeps forgetting this device's session (it may be restarting) — try again in a minute"
	case he.Status == http.StatusUnauthorized && he.Body == api.ErrUnknownIdentity && linkedDevice.Load():
		return "the relay no longer knows this device: it was unlinked (or the account was set up from scratch). To add it again: `itter burn` here, then run `itter`"
	case he.Status == http.StatusUnauthorized && he.Body == api.ErrUnknownIdentity:
		return "the relay no longer knows this device: its identity was released or replaced. To use this device again: `itter burn`, then run `itter`"
	case he.Status == http.StatusUnauthorized:
		return "the relay did not accept that this request came from this device — try again"
	case he.Status == http.StatusTooManyRequests && he.Body == api.ErrInboxFull:
		return "the recipient has too many unread messages from you waiting — the rest stay queued"
	case he.Status == http.StatusTooManyRequests:
		return "the relay is rate-limiting you — try again in a minute"
	case he.Status >= 500:
		return fmt.Sprintf("the relay has a problem (%d) — try again later", he.Status)
	}
	return fmt.Sprintf("the relay refused: %s", clean(he.Body)) // relay text is untrusted too
}

// retryable reports whether err is worth retrying later without any change.
func retryable(err error) bool {
	st := relay.Status(err)
	return st == 0 || st >= 500 || st == http.StatusTooManyRequests || st == http.StatusRequestTimeout
}

func stripAt(s string) string { return strings.TrimPrefix(strings.TrimSpace(s), "@") }

// resolve maps what the user typed to the spelling of a known contact.
func (a *app) resolve(name string) string {
	name = stripAt(name)
	for _, c := range a.v.ContactList() {
		if strings.EqualFold(c.Name, name) {
			return c.Name
		}
	}
	return name
}

// safetyNumber is made of the two ACCOUNT identities, so it is the same on
// all of one's devices and does not change when devices come and go.
func (a *app) safetyNumber(theirs []byte) string {
	return pqc.SafetyNumber(a.v.AccountIdentity(), theirs)
}

const firstContactNotice = "New conversation with @%s, end-to-end encrypted. Not verified yet: `sn @%s` shows the safety number to compare."

// announceChange tells the user that a contact shows a different identity.
// An identity never changes without the user saying so. The safety number
// gets a line of its own, so it can be read out and compared. It runs inside
// v.Update and returns the number of lines added.
func (a *app) announceChange(peer string, identity []byte, verified bool) int {
	than := "before"
	if verified {
		than = "the one you verified"
	}
	a.v.AddSystem(peer, fmt.Sprintf("IDENTITY CHANGED: @%s now shows a different identity than %s. That usually means they set up DMs from scratch (a reinstall, or their first device was lost); it is also what an attacker in the middle looks like. Until you decide, nothing is sent to it and its messages are held unread. The new safety number is:", peer, than))
	a.v.AddSystem(peer, a.safetyNumber(identity))
	a.v.AddSystem(peer, fmt.Sprintf("Compare it with @%s over a channel you trust, then: accept @%s", peer, peer))
	return 3
}

// --- the relay's directory ---

// dirInfo is a VERIFIED copy of what the relay lists for an account: every
// device in it is vouched for by the account identity's signature, and every
// signed prekey by its device.
type dirInfo struct {
	name     string
	identity []byte                       // the account identity
	list     *pqc.DeviceList              // nil: no linked devices
	bundles  map[string]*pqc.PublicBundle // device id -> keys to start a session with
}

func (d *dirInfo) keys() [][]byte {
	if d.list == nil {
		return nil
	}
	return d.list.Keys
}

// has reports whether key is one of the account's devices.
func (d *dirInfo) has(key []byte) bool {
	return d != nil && (pqc.IdentityEqual(d.identity, key) || d.list.Has(key))
}

// devices lists the devices that can be written to, without skip.
func (d *dirInfo) devices(skip string) []string {
	out := make([]string, 0, len(d.bundles))
	for id := range d.bundles {
		if id != skip {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// verifyDirectory checks everything a directory entry claims. Nothing the
// relay says about an account is used before it has passed here.
func verifyDirectory(peer string, d *api.Directory) (*dirInfo, error) {
	if d == nil || !api.ValidUsername(d.Username) || !strings.EqualFold(d.Username, peer) {
		return nil, errors.New("it is for a different account")
	}
	if _, err := pqc.DecodeIdentityKey(d.Identity); err != nil {
		return nil, err
	}
	if d.List != nil {
		if err := d.List.Verify(d.Identity, d.Username); err != nil {
			return nil, err
		}
	}
	out := &dirInfo{name: d.Username, identity: d.Identity, list: d.List, bundles: map[string]*pqc.PublicBundle{}}
	for _, b := range d.Devices {
		if b == nil || !strings.EqualFold(b.Username, d.Username) || !out.has(b.Identity) {
			return nil, errors.New("it names a device that the account identity does not vouch for")
		}
		if _, err := b.Verify(); err != nil {
			return nil, err
		}
		id := pqc.IdentityID(b.Identity)
		if out.bundles[id] != nil {
			return nil, errors.New("it names a device twice")
		}
		b.Username = d.Username
		out.bundles[id] = b
	}
	if len(out.bundles) == 0 || len(out.bundles) > api.MaxDevices {
		return nil, errors.New("it lists no usable device")
	}
	return out, nil
}

// directory asks the relay what it lists for an account: nil if nothing.
// Replacing a listed identity takes its owner's hash-based signature or the
// recovery code, so the listing is a better witness of who an account is
// than the mere fact that a message arrived in its name.
func (a *app) directory(peer string) (*dirInfo, error) {
	d, err := a.rc.Directory(peer)
	switch st := relay.Status(err); {
	case st == http.StatusNotFound || st == http.StatusGone:
		return nil, nil
	case err != nil:
		return nil, err
	}
	info, err := verifyDirectory(peer, d)
	if err != nil {
		return nil, userErrf("the relay delivered an invalid directory entry for @%s (%v)", peer, err)
	}
	return info, nil
}

// earlyNotice is for messages of a session whose handshake this device never
// got: the relay took it from the sender and then did not deliver it (the
// sender was ignored at the time, or this device was away for too long).
const earlyNotice = "%d message(s) from @%s could not be read: the key exchange they belong to never reached this device. Their device sends it again by itself (after some minutes at first, after a day at the latest). To set up a session right now, write to @%s — and ask them to send these again."

const staleNotice = "Dropped %d message(s) sent in @%s's name by a device or identity the relay does not list for that account: an old device of theirs, or someone pretending to be them."

// learn applies a verified directory entry to what is on record for peer. It
// runs inside v.Update. It reports whether the entry is for the identity on
// record, so that its devices may be talked to; if the relay lists a
// different identity, that one becomes pending and the user is told.
func (a *app) learn(peer string, d *dirInfo, quiet bool, b *batch) bool {
	me, _ := a.v.Me()
	if peer == me {
		if !pqc.IdentityEqual(d.identity, a.v.AccountIdentity()) {
			return false
		}
		a.v.SetOwnDevices(d.identity, d.list, d.devices(a.v.DeviceID()))
		return true
	}
	info, _ := a.v.ContactInfo(peer)
	switch a.v.Observe(peer, d.identity) {
	case vault.IdentityBlocked:
		if a.v.Announce(peer) {
			b.added += a.announceChange(peer, d.identity, info.Verified)
		}
		return false
	case vault.IdentityNew:
		a.v.AddSystem(peer, fmt.Sprintf(firstContactNotice, peer, peer))
		b.added++
		a.v.SetDevices(peer, d.list.Version(), d.keys(), d.devices(""))
	default:
		added, taken := a.v.SetDevices(peer, d.list.Version(), d.keys(), d.devices(""))
		if taken && added > 0 && !quiet {
			a.v.AddSystem(peer, fmt.Sprintf("@%s linked a new device (%d in use now). The identity you know vouches for it; the safety number stays the same.", peer, len(d.bundles)))
			b.added++
		}
	}
	return true
}

// checkDirectory settles what to do about messages from a device or identity
// that is not on record for peer, by asking the relay's directory. It must
// not run inside v.Update. It returns how many lines it added.
func (a *app) checkDirectory(peer string) int {
	d, err := a.directory(peer)
	if err != nil {
		return 0 // cannot tell right now; the next pull tries again
	}
	b := newBatch()
	_ = a.v.Update(func() error {
		info, known := a.v.ContactInfo(peer)
		switch {
		case d == nil:
			// The relay lists no identity for the account (any more): what
			// was held cannot be checked against anything.
			b.stale[peer] += len(a.v.TakeHeld(peer))
			a.v.DropPending(peer)
		case !known || pqc.IdentityEqual(d.identity, info.Identity):
			// First contact, or the identity on record: its devices are
			// whatever its signed list says. What was held is looked at again.
			held := a.v.TakeHeld(peer)
			a.v.DropPending(peer)
			if a.learn(peer, d, false, b) {
				a.replay(peer, held, b)
			}
		default:
			// The relay lists a different identity. The user decides; what
			// is held stays held.
			a.learn(peer, d, false, b)
		}
		a.finish(b)
		return nil
	})
	return b.added
}

// replay processes messages that were held back. It runs inside v.Update.
func (a *app) replay(peer string, held [][]byte, b *batch) {
	for _, raw := range held {
		var w pqc.WireMsg
		if json.Unmarshal(raw, &w) == nil {
			a.processWire(peer, &w, true, b)
		}
	}
}

func errBlocked(name string) error {
	return userErrf("@%s shows a different identity than the one on record — not sent. Compare the new safety number (`sn @%s`), then `accept @%s`", name, name, name)
}

// errGone and errChanged are what the relay answers when a queued message
// can no longer be delivered; prepare reports the same way.
var (
	errGone    = &relay.HTTPError{Status: http.StatusGone, Body: api.ErrNoIdentity}
	errChanged = &relay.HTTPError{Status: http.StatusConflict, Body: api.ErrIdentityChanged}
)

// prepare makes sure there is a session with every device of target that
// messages have to go to. It asks the relay only when something is missing
// on record, or when refresh says that what is on record is out of date. It
// returns the account name as itter spells it.
func (a *app) prepare(target string, refresh bool) (string, error) {
	me, id := a.v.Me()
	self := target == me
	info, known := a.v.ContactInfo(target)
	have := a.v.SessionDevices(target)
	if known && !refresh {
		reach := a.v.Reach(target)
		complete := len(reach) > 0
		for _, dev := range reach {
			complete = complete && slices.Contains(have, dev)
		}
		if complete {
			return target, nil
		}
	}

	// What does the relay list? One-time prekeys are only taken for devices
	// there is no session with yet.
	var raw *api.Directory
	var err error
	if known {
		if raw, err = a.rc.Directory(target); err == nil {
			var fresh []string
			for _, bun := range raw.Devices {
				if bun != nil && !slices.Contains(have, pqc.IdentityID(bun.Identity)) {
					fresh = append(fresh, pqc.IdentityID(bun.Identity))
				}
			}
			if len(fresh) > 0 {
				raw, err = a.rc.Claim(a.auth(), target, fresh)
			}
		}
	} else {
		raw, err = a.rc.Claim(a.auth(), target, nil)
	}
	if err != nil {
		return "", err
	}
	d, err := verifyDirectory(target, raw)
	if err != nil {
		return "", userErrf("the relay delivered an invalid directory entry for @%s (%v) — not sending", target, err)
	}
	if self && !pqc.IdentityEqual(d.identity, a.v.AccountIdentity()) {
		return "", userErrf("the relay lists a different identity for your own account — run `itter status`")
	}

	// Handshakes are slow (a hash-based signature each): outside the lock.
	sessions := map[string]*pqc.Session{}
	if self || !known || pqc.IdentityEqual(d.identity, info.Identity) {
		for _, dev := range d.devices("") {
			if slices.Contains(have, dev) || (self && dev == a.v.DeviceID()) {
				continue
			}
			sess, err := pqc.Initiate(id, me, d.bundles[dev])
			if err != nil {
				return "", userErrf("the relay delivered an invalid key bundle for @%s (%v) — not sending", d.name, err)
			}
			sessions[dev] = sess
		}
	}
	ok := false
	err = a.v.Update(func() error {
		b := newBatch()
		if ok = a.learn(d.name, d, false, b); !ok {
			return nil
		}
		now := a.v.SessionDevices(d.name) // another itter process may have been faster
		for dev, sess := range sessions {
			if !slices.Contains(now, dev) {
				if err := a.v.InstallSession(d.name, sess); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errBlocked(d.name)
	}
	return d.name, nil
}

// sendOutcome says what became of a message.
type sendOutcome struct {
	Target string // the account name as itter spells it
	Status int    // vault.StatusSent, StatusQueued or StatusFailed
	Note   string // for StatusQueued: why it is not out yet
}

// send encrypts text for target, saves it, and then tries to deliver it. An
// error means nothing was queued (and says why); otherwise the outcome tells
// whether the relay has it or it waits in the outbox.
func (a *app) send(target, text string) (sendOutcome, error) {
	return a.sendPayload(target, text, nil)
}

// sealAll encrypts payload once for each device of target. It runs inside
// v.Update. Nothing is encrypted unless every device can be served.
func (a *app) sealAll(target, msgID string, payload []byte) (*vault.QueuedWire, error) {
	info, _ := a.v.ContactInfo(target)
	reach, have := a.v.Reach(target), a.v.SessionDevices(target)
	if len(reach) == 0 || len(info.Identity) == 0 {
		return nil, vault.ErrNoSession
	}
	for _, dev := range reach {
		if !slices.Contains(have, dev) {
			return nil, vault.ErrNoSession
		}
	}
	q := &vault.QueuedWire{ID: msgID, Target: target, ToID: pqc.IdentityID(info.Identity),
		Wires: map[string][]byte{}, Init: map[string]string{}, Payload: payload}
	for _, dev := range reach {
		if err := a.sealFor(q, dev); err != nil {
			return nil, err
		}
	}
	return q, nil
}

func (a *app) sealFor(q *vault.QueuedWire, dev string) error {
	w, hsID, err := a.v.Seal(q.Target, dev, q.Payload)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return err
	}
	q.Wires[dev] = raw
	if hsID != nil {
		q.Init[dev] = hex.EncodeToString(hsID)
	}
	return nil
}

func (a *app) sendPayload(target, text string, control []byte) (sendOutcome, error) {
	target = a.resolve(target)
	me, _ := a.v.Me()
	switch {
	case !api.ValidUsername(target):
		return sendOutcome{}, userErrf("%q is not a valid itter username", target)
	case strings.EqualFold(target, me):
		return sendOutcome{}, userErrf("you cannot message yourself")
	}
	payload := control
	if control == nil {
		text = strings.TrimSpace(clean(text))
		switch {
		case text == "":
			return sendOutcome{}, userErrf("nothing to send")
		case len(text) > api.MaxTextLen:
			return sendOutcome{}, userErrf("message too long (%d bytes, the limit is %d)", len(text), api.MaxTextLen)
		}
		payload = pqc.PackInner(text)
	}

	if info, _ := a.v.ContactInfo(target); len(info.Pending) > 0 {
		a.checkDirectory(target) // settles it if it can be settled without the user
		if info, _ = a.v.ContactInfo(target); len(info.Pending) > 0 {
			// The identity on record is gone and the new one is not accepted:
			// there is nobody to send to.
			return sendOutcome{}, errBlocked(target)
		}
	}

	msgID, ts := randID(), time.Now().Unix()
	for attempt := 0; ; attempt++ {
		name, err := a.prepare(target, false)
		switch {
		case relay.Status(err) == http.StatusNotFound:
			return sendOutcome{}, userErrf("there is no itter user @%s", target)
		case relay.Status(err) == http.StatusGone:
			return sendOutcome{}, userErrf("@%s has not set up DMs (they need to run `itter` once)", target)
		case err != nil && relay.Status(err) == 0 && !isUserErr(err), err != nil && relay.Status(err) >= 400:
			return sendOutcome{}, userErrf("%s. Not every device of @%s has a session yet, so the message could not be queued either", explain(err), target)
		case err != nil:
			return sendOutcome{}, err
		}
		target = name
		err = a.v.Update(func() error {
			q, err := a.sealAll(target, msgID, payload)
			if err != nil {
				return err
			}
			if control == nil {
				a.v.AddMessage(target, vault.ChatMsg{ID: msgID, IsOut: true, Status: vault.StatusQueued, TS: ts, Text: text})
			}
			a.v.QueueBatch(*q)
			return nil
		})
		if errors.Is(err, vault.ErrNoSession) && attempt == 0 {
			continue // another itter process reset the session meanwhile
		}
		if err != nil {
			return sendOutcome{}, err
		}
		break
	}
	// The ratchet state and the ciphertext are on disk. Now it may leave.
	var ferr error = errOffline
	if !a.offline.Load() {
		ferr = a.flush()
	}
	out := sendOutcome{Target: target, Status: vault.StatusSent}
	for _, q := range a.v.OutboxSnapshot() {
		if q.ID == msgID {
			out.Status = vault.StatusQueued
			if ferr != nil {
				out.Note = explain(ferr)
			}
		}
	}
	if control == nil && out.Status == vault.StatusSent {
		for _, m := range a.v.GetMessages(target) {
			if m.ID == msgID && m.Status == vault.StatusFailed {
				out.Status = vault.StatusFailed
			}
		}
	}
	return out, nil
}

func isUserErr(err error) bool {
	var ue *userErr
	return errors.As(err, &ue)
}

// syncSent tells one's other devices about a message the relay has taken, so
// the conversation looks the same on all of them. Best effort: the copy is
// queued like any message, and it reports whether one was.
func (a *app) syncSent(peer, text string, ts int64) bool {
	if l := a.v.OwnDevices(); !a.v.IsLinked() && (l == nil || len(l.Keys) == 0) {
		return false // the only device of this account
	}
	me, _ := a.v.Me()
	if _, err := a.prepare(me, false); err != nil {
		return false
	}
	queued := false
	_ = a.v.Update(func() error {
		q, err := a.sealAll(me, randID(), pqc.PackSync(peer, text, ts))
		if err == nil {
			a.v.QueueBatch(*q)
			queued = true
		}
		return nil
	})
	return queued
}

// refit brings a queued message in line with the recipient's current
// devices: a device linked since gets its own copy, a removed one is left
// out. It reports relay-style errors when there is nobody left to send to.
func (a *app) refit(q *vault.QueuedWire) error {
	if _, err := a.prepare(q.Target, true); err != nil {
		if isUserErr(err) {
			return errChanged // the identity is not the one this was encrypted for
		}
		return err
	}
	var rerr error
	err := a.v.Update(func() error {
		info, _ := a.v.ContactInfo(q.Target)
		reach := a.v.Reach(q.Target)
		switch {
		case pqc.IdentityID(info.Identity) != q.ToID:
			rerr = errChanged
		case len(reach) == 0:
			rerr = errGone
		}
		if rerr != nil {
			return nil
		}
		for dev := range q.Wires {
			if !slices.Contains(reach, dev) {
				delete(q.Wires, dev)
				delete(q.Init, dev)
			}
		}
		for _, dev := range reach {
			if _, ok := q.Wires[dev]; ok {
				continue
			}
			if len(q.Payload) == 0 {
				rerr = errChanged // queued by an older itter: there is nothing to encrypt again
				return nil
			}
			if q.Init == nil {
				q.Init = map[string]string{}
			}
			if err := a.sealFor(q, dev); err != nil {
				return err
			}
		}
		cp := *q
		a.v.EditOutbox(q.ID, func(old *vault.QueuedWire) { old.Wires, old.Init = cp.Wires, cp.Init })
		return nil
	})
	if err != nil {
		return err
	}
	return rerr
}

// deliver posts one queued message. If the recipient's devices changed in
// the meantime it brings the message up to date and tries once more.
func (a *app) deliver(q *vault.QueuedWire) error {
	err := a.rc.Send(a.auth(), q.Target, q.ToID, q.Wires)
	if !relay.Is(err, api.ErrDevicesChanged) {
		return err
	}
	if err := a.refit(q); err != nil {
		return err
	}
	return a.rc.Send(a.auth(), q.Target, q.ToID, q.Wires)
}

// flush delivers the outbox in order. Per recipient it stops at the first
// message that cannot go out yet, so messages never overtake each other. It
// returns the reason something is still queued (nil if nothing is).
func (a *app) flush() error {
	a.flushMu.Lock()
	defer a.flushMu.Unlock()
	me, _ := a.v.Me()
	sent, pending, err := a.flushPass(nil)
	if err != nil {
		return err
	}
	// One's other devices are told what went out — once the relay has it, so
	// they never show as sent what is still waiting here.
	copies := false
	for _, q := range sent {
		if q.Target == me {
			continue
		}
		if im, err := pqc.UnpackInner(q.Payload); err == nil && im.Kind == "" && im.Text != "" {
			copies = a.syncSent(q.Target, im.Text, im.TS) || copies
		}
	}
	if copies {
		if _, _, err := a.flushPass(func(q *vault.QueuedWire) bool { return q.Target == me }); err != nil {
			return err
		}
	}
	return pending
}

// flushPass goes through the outbox once (only: just those entries). It
// returns what the relay took, the reason something is still queued, and an
// error if nothing more can be done right now.
func (a *app) flushPass(only func(*vault.QueuedWire) bool) (sent []vault.QueuedWire, pending, fatal error) {
	me, _ := a.v.Me()
	stuck := map[string]bool{}
	for _, q := range a.v.OutboxSnapshot() {
		if stuck[q.Target] || (only != nil && !only(&q)) {
			continue
		}
		err := a.deliver(&q)
		var uerr error
		switch {
		case err == nil:
			sent = append(sent, q)
			uerr = a.v.Update(func() error {
				a.v.RemoveOutbox(q.ID)
				a.v.SetStatus(q.Target, q.ID, vault.StatusSent)
				// The relay has the handshakes these messages carried, and it
				// delivers in order: no need to attach them again for now.
				for dev, hs := range q.Init {
					if id, err := hex.DecodeString(hs); err == nil {
						a.v.HandshakeDelivered(q.Target, dev, id)
					}
				}
				return nil
			})
		case q.Target == me && (!retryable(err) || relay.Is(err, api.ErrInboxFull)) && relay.Status(err) != http.StatusUnauthorized:
			// A copy for one's own devices that cannot be delivered is not worth
			// a word, and not worth keeping either if they have no room for it.
			uerr = a.v.Update(func() error { a.v.RemoveOutbox(q.ID); return nil })
		case relay.Is(err, api.ErrIdentityChanged), relay.Is(err, api.ErrNoIdentity):
			// The recipient no longer has the identity this was encrypted
			// for. Nothing queued for them can ever be read.
			gone := relay.Is(err, api.ErrNoIdentity)
			stuck[q.Target] = true
			uerr = a.v.Update(func() error {
				n := a.v.FailOutboxFor(q.Target)
				a.v.RetireSession(q.Target)
				if gone {
					a.v.AddSystem(q.Target, fmt.Sprintf("@%s has no DM identity right now (they reset it, or have not finished setup). %d message(s) were NOT delivered.", q.Target, n))
				} else {
					a.v.AddSystem(q.Target, fmt.Sprintf("%d message(s) to @%s were NOT delivered: the relay no longer lists the identity they were encrypted for.", n, q.Target))
				}
				return nil
			})
			if uerr == nil && !gone {
				a.checkDirectory(q.Target) // shows the new safety number
			}
		case retryable(err) || relay.Status(err) == http.StatusUnauthorized || relay.Is(err, api.ErrDevicesChanged):
			stuck[q.Target] = true
			if q.Target != me || pending == nil {
				pending = err
			}
			if relay.Status(err) == http.StatusUnauthorized {
				return sent, pending, err // our own credentials are the problem: nothing will go out
			}
		default: // the relay will never take this message
			uerr = a.v.Update(func() error {
				a.v.RemoveOutbox(q.ID)
				a.v.SetStatus(q.Target, q.ID, vault.StatusFailed)
				a.v.AddSystem(q.Target, fmt.Sprintf("A message to @%s was rejected and NOT delivered: %s.", q.Target, explain(err)))
				return nil
			})
		}
		if uerr != nil {
			return sent, pending, uerr
		}
	}
	return sent, pending, nil
}

func wireDigest(w *pqc.WireMsg) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00", w.Type, w.From, w.Dev)
	h.Write(w.Payload)
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// batch collects what happened while a group of messages was processed.
type batch struct {
	added   int             // lines added to conversations
	unread  map[string]int  // undecryptable messages per sender
	early   map[string]int  // messages whose handshake never arrived, per sender
	stale   map[string]int  // messages from a device or identity the relay does not list for the sender
	lost    map[string]int  // messages that could not be held (too many waiting)
	pending map[string]bool // senders whose devices have to be checked against the directory

	// For a sender we have never talked to: what the relay's directory
	// lists for that account (nil: nothing), looked up before the batch.
	dir   *dirInfo
	dirOK bool
}

func newBatch() *batch {
	return &batch{unread: map[string]int{}, early: map[string]int{}, stale: map[string]int{}, lost: map[string]int{}, pending: map[string]bool{}}
}

// hold keeps a message aside until the directory has been asked about its
// sender (or, for a new identity, until the user has decided).
func (a *app) hold(sender string, w *pqc.WireMsg, b *batch) {
	raw, _ := json.Marshal(w)
	if !a.v.HoldAside(sender, raw) {
		b.lost[sender]++
	}
	b.pending[sender] = true
}

// processWire handles one message from the relay. It runs inside v.Update.
// held is true when a message that was kept aside is looked at again.
func (a *app) processWire(sender string, w *pqc.WireMsg, held bool, b *batch) {
	if w.From != sender {
		return // the relay filed it under the wrong sender
	}
	if !held && !a.v.FirstTime(wireDigest(w)) {
		return // redelivery of something already processed
	}
	if slices.Contains(a.v.IgnoreList(), sender) {
		return // the relay keeps these away already; this is for what was on its way
	}
	dev := w.Dev
	if !devRE.MatchString(dev) {
		dev = ""
	}
	var pt []byte
	var err error
	switch w.Type {
	case pqc.WireInitial:
		pt, err = a.processInitial(sender, w, held, b)
		if pt == nil && err == nil {
			return
		}
	case pqc.WireEnvelope:
		if a.frozen(sender) {
			if a.v.HasDeviceID(sender, dev) || held {
				b.stale[sender]++ // the identity on record is not listed any more
			} else {
				a.hold(sender, w, b) // most likely the new identity's session
			}
			return
		}
		var ep *pqc.EnvelopePayload
		if ep, err = pqc.ParseEnvelope(w); err == nil {
			pt, err = a.v.Open(sender, dev, ep.Env)
		}
		if err != nil && !errors.Is(err, pqc.ErrDuplicate) && !held {
			if info, _ := a.v.ContactInfo(sender); info.Held > 0 {
				// Its handshake is among the messages that are being held:
				// it has to wait with them, in order.
				a.hold(sender, w, b)
				return
			}
		}
		if err != nil && !errors.Is(err, pqc.ErrDuplicate) && dev != "" && !a.v.HadSessionWith(sender, dev) {
			b.early[sender]++ // not a broken session: there never was one
			return
		}
	default:
		return
	}
	if errors.Is(err, pqc.ErrDuplicate) {
		return
	}
	if err != nil {
		b.unread[sender]++
		return
	}
	im, err := pqc.UnpackInner(pt)
	if err != nil {
		b.unread[sender]++
		return
	}
	text := strings.TrimSpace(clean(im.Text))
	if len(text) > 4*api.MaxTextLen {
		text = text[:4*api.MaxTextLen]
	}
	if me, _ := a.v.Me(); sender == me {
		// One of this account's own devices. The only thing it has to say is
		// what it sent to someone.
		if im.Kind == pqc.KindSync && api.ValidUsername(im.Peer) && !strings.EqualFold(im.Peer, me) {
			peer := a.resolve(im.Peer)
			a.v.AddMessage(peer, vault.ChatMsg{ID: randID(), IsOut: true, Status: vault.StatusSent, TS: a.v.IncomingTS(peer, im.TS), Text: text})
			b.added++
		}
		return
	}
	switch im.Kind {
	case "":
		a.v.AddMessage(sender, vault.ChatMsg{ID: randID(), Status: vault.StatusSent, TS: a.v.IncomingTS(sender, im.TS), Text: text})
	case pqc.KindReset:
		a.v.AddSystem(sender, fmt.Sprintf("@%s started a fresh session.", sender))
	default:
		return // a kind from a newer itter, or one only one's own devices may send
	}
	b.added++
}

var devRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// frozen reports whether the relay lists a different identity for peer than
// the one on record and the user has not decided yet. Until then the
// conversation stands still in both directions: the identity on record was
// given up by its owner (or taken from them), so nothing in its name is
// shown any more either.
func (a *app) frozen(peer string) bool {
	info, _ := a.v.ContactInfo(peer)
	return len(info.Pending) > 0 && info.Announced
}

// processInitial handles a message that carries a handshake. It returns the
// plaintext, an error if the message is unreadable, or (nil, nil) if there is
// nothing to show (a replay, or kept aside).
func (a *app) processInitial(sender string, w *pqc.WireMsg, held bool, b *batch) ([]byte, error) {
	ip, err := pqc.ParseInitial(w)
	if err != nil {
		return nil, err
	}
	hsID := ip.HS.HandshakeID()
	if a.v.KnownHandshake(sender, hsID) { // repeated until the relay took one
		if a.frozen(sender) {
			b.stale[sender]++
			return nil, nil
		}
		return a.v.Open(sender, pqc.IdentityID(ip.HS.Identity), ip.Env)
	}
	if a.v.HandshakeSeen(sender, hsID) {
		return nil, nil // an old handshake whose session is gone: never resurrect it
	}
	me, id := a.v.Me()
	sess, err := pqc.Respond(id, me, a.v.FindSPK(ip.HS.SPKID), a.v.FindOTPK(ip.HS.OTPKID), ip.HS)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(sess.TheirUsername, sender) {
		return nil, errors.New("handshake was signed for a different account name")
	}
	pt, err := sess.Decrypt(ip.Env)
	if err != nil {
		return nil, err
	}
	// The handshake is genuine: signed by the device key ip.HS.Identity for
	// this pair of account names, and the first message decrypts. Whether
	// that device belongs to the account is a separate question, and the
	// answer has to come from the account identity.
	_, known := a.v.ContactInfo(sender)
	switch {
	case known && a.v.ValidDevice(sender, ip.HS.Identity):
		if a.frozen(sender) {
			b.stale[sender]++
			return nil, nil
		}
	case !known && b.dirOK && b.dir.has(ip.HS.Identity):
		// Someone new, and the identity the relay lists for the account
		// vouches for this device: trust on first use.
		if !a.learn(sender, b.dir, false, b) {
			b.stale[sender]++
			return nil, nil
		}
	case (!known && b.dirOK) || held:
		// The relay's directory has been asked and does not know the device.
		b.stale[sender]++
		a.v.ConsumeOTPK(ip.HS.OTPKID)
		return nil, nil
	default:
		// A contact we know, a device we do not: a newly linked one, or a
		// new identity. The message waits until the directory was asked.
		a.hold(sender, w, b)
		return nil, nil
	}
	if err := a.v.InstallSession(sender, sess); err != nil {
		return nil, err
	}
	a.v.MarkHandshake(sender, hsID)
	a.v.ConsumeOTPK(ip.HS.OTPKID)
	return pt, nil
}

// finish adds the notices a batch calls for. It runs inside v.Update.
func (a *app) finish(b *batch) {
	me, _ := a.v.Me()
	for sender, n := range b.unread {
		if sender == me {
			continue // a lost copy from one's own device is not worth a word
		}
		a.v.AddSystem(sender, fmt.Sprintf("%d message(s) from @%s could not be decrypted and were dropped. If this keeps happening, `reset @%s` and ask them to send again.", n, sender, sender))
		b.added++
	}
	for sender, n := range b.early {
		if sender == me {
			continue
		}
		a.v.AddSystem(sender, fmt.Sprintf(earlyNotice, n, sender, sender))
		b.added++
	}
	for sender, n := range b.stale {
		if n > 0 && sender != me && a.v.AlertDue(sender) {
			a.v.AddSystem(sender, fmt.Sprintf(staleNotice, n, sender))
			b.added++
		}
	}
	for sender, n := range b.lost {
		if sender == me {
			continue
		}
		a.v.AddSystem(sender, fmt.Sprintf("%d more message(s) from @%s were dropped: too many are waiting for a decision. They need to be sent again.", n, sender))
		b.added++
	}
}

const maxPages = 40 // per sender and pull; the rest comes with the next pull

// pull fetches and processes waiting messages. With wait > 0 it blocks until
// something arrives or wait seconds pass. It returns how many lines were
// added to conversations.
func (a *app) pull(wait int) (int, error) {
	senders, err := a.rc.Inbox(a.auth(), wait)
	if err != nil {
		return 0, err
	}
	names := make([]string, 0, len(senders))
	for s := range senders {
		if api.ValidUsername(s) { // never trust names from the relay
			names = append(names, s)
		}
	}
	sort.Strings(names)
	total := 0
	var first error
	for _, sender := range names {
		n, err := a.pullFrom(sender)
		total += n
		if err != nil {
			if retryable(err) || relay.Status(err) == http.StatusUnauthorized {
				return total, err // the relay or our login is the problem, not this sender
			}
			if first == nil {
				first = err // this sender's messages stay on the relay; go on with the others
			}
		}
	}
	// Whatever is still held without the user having been asked: the
	// directory could not be reached earlier.
	for _, c := range a.v.ContactList() {
		if c.Held > 0 && !c.Announced {
			total += a.checkDirectory(c.Name)
		}
	}
	return total, first
}

func (a *app) pullFrom(sender string) (int, error) {
	total := 0
	for page := 0; page < maxPages; page++ {
		items, err := a.rc.InboxFrom(a.auth(), sender)
		if err != nil {
			return total, err
		}
		if len(items) == 0 {
			return total, nil
		}
		b := newBatch()
		if _, known := a.v.ContactInfo(sender); !known {
			// Someone new. Before trusting the keys their first message
			// brings along, see what the relay lists for that account.
			if b.dir, err = a.directory(sender); err != nil {
				return total, err // nothing is acknowledged: it all comes again
			}
			b.dirOK = true
		}
		ids := make([]int64, 0, len(items))
		err = a.v.Update(func() error {
			for i := range items {
				ids = append(ids, items[i].ID)
				a.processWire(sender, &items[i].Msg, false, b)
			}
			a.finish(b)
			return nil
		})
		total += b.added
		if err != nil {
			return total, err // not saved: do not ack, the relay will redeliver
		}
		// Saved. Only now may the relay delete them. If the ack is lost they
		// come again and are recognised as already processed.
		if err := a.rc.Ack(a.auth(), ids); err != nil {
			return total, err
		}
		if b.pending[sender] {
			total += a.checkDirectory(sender)
		}
	}
	return total, nil
}

// accept switches a contact to its new identity and reads the messages that
// were held for it.
func (a *app) accept(peer string) (string, error) {
	peer = a.resolve(peer)
	info, _ := a.v.ContactInfo(peer)
	if len(info.Pending) == 0 {
		return "", userErrf("nothing to accept for @%s", peer)
	}
	// The new identity's devices are whatever its own signed list says.
	d, err := a.directory(peer)
	if err != nil {
		return "", userErrf("%s — accepting needs the relay, try again", explain(err))
	}
	if d == nil || !pqc.IdentityEqual(d.identity, info.Pending) {
		a.checkDirectory(peer)
		return "", userErrf("@%s's identity is not the one you were shown any more — see the chat", peer)
	}
	b := newBatch()
	var sn string
	nHeld := 0
	err = a.v.Update(func() error {
		now, _ := a.v.ContactInfo(peer)
		if !pqc.IdentityEqual(now.Pending, d.identity) {
			return userErrf("@%s's identity changed again — nothing was accepted", peer)
		}
		held, err := a.v.Accept(peer)
		if err != nil {
			return &userErr{err.Error()}
		}
		sn, nHeld = a.safetyNumber(d.identity), len(held)
		a.v.AddSystem(peer, fmt.Sprintf("You accepted @%s's new identity (safety number %s). It is not verified yet: `verify @%s` once you have compared it.", peer, sn, peer))
		a.learn(peer, d, true, b)
		a.replay(peer, held, b)
		a.finish(b)
		return nil
	})
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("Accepted @%s's new identity, safety number %s. Not verified yet.", peer, sn)
	if nHeld > 0 {
		msg += fmt.Sprintf(" The %d held message(s) are in the chat now.", nHeld)
	}
	return msg, nil
}

// reset forgets all sessions with peer and starts fresh ones right away, so
// the other side switches too.
func (a *app) reset(peer string) (string, error) {
	peer = a.resolve(peer)
	if _, known := a.v.ContactInfo(peer); !known {
		return "", userErrf("no conversation with @%s", peer)
	}
	err := a.v.Update(func() error {
		a.v.ResetSessions(peer)
		a.v.FailOutboxFor(peer)
		a.v.AddSystem(peer, fmt.Sprintf("You reset the session with @%s.", peer))
		return nil
	})
	if err != nil {
		return "", err
	}
	if _, err := a.sendPayload(peer, "", pqc.PackControl(pqc.KindReset)); err != nil {
		return fmt.Sprintf("Session with @%s reset. A fresh one starts with your next message (%s).", peer, explain(err)), nil
	}
	return fmt.Sprintf("Session with @%s reset; a fresh one is set up.", peer), nil
}

func (a *app) setVerified(peer string, verified bool) (string, error) {
	peer = a.resolve(peer)
	err := a.v.Update(func() error {
		if err := a.v.SetVerified(peer, verified); err != nil {
			return &userErr{err.Error()}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if verified {
		info, _ := a.v.ContactInfo(peer)
		return fmt.Sprintf("@%s marked as verified for safety number %s.", peer, a.safetyNumber(info.Identity)), nil
	}
	return fmt.Sprintf("@%s is no longer marked as verified.", peer), nil
}

// --- prekeys ---

const (
	otpkBatch     = 20
	otpkLow       = 5
	spkMaxAge     = 7 * 24 * time.Hour
	keyCheckEvery = 10 * time.Minute
)

// publishPreKeys generates prekeys, saves them, and only then uploads the
// public halves (a prekey on the relay that we cannot answer would break the
// first message of whoever gets it).
func (a *app) publishPreKeys(newSPK bool, otpks int) error {
	_, id := a.v.Me()
	var first uint32
	if err := a.v.Update(func() error { first = a.v.ReservePreKeyIDs(otpks + 1); return nil }); err != nil {
		return err
	}
	var spk *pqc.PreKey
	var spkPub *pqc.PreKeyPublic
	var err error
	if cur := a.v.LatestSPK(); cur != nil && !newSPK {
		spk = cur
		if spkPub, err = cur.Public(); err != nil {
			return err
		}
	} else {
		newSPK = true
		if spk, spkPub, err = pqc.GenerateSignedPreKey(id, first); err != nil {
			return err
		}
	}
	var privs []*pqc.PreKey
	var pubs []*pqc.PreKeyPublic
	for i := 0; i < otpks; i++ {
		k, kp, err := pqc.GenerateOneTimePreKey(first + 1 + uint32(i))
		if err != nil {
			return err
		}
		privs, pubs = append(privs, k), append(pubs, kp)
	}
	err = a.v.Update(func() error {
		if newSPK {
			a.v.AddPreKeys(spk, privs)
		} else {
			a.v.AddPreKeys(nil, privs)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.rc.UploadKeys(a.auth(), spkPub, spk.Sig, pubs)
}

// maintain tops up one-time prekeys and rotates the signed prekey. It is
// cheap to call often: it asks the relay at most every few minutes.
func (a *app) maintain() error {
	now := time.Now()
	if now.Unix()-a.v.KeyCheck() < int64(keyCheckEvery/time.Second) {
		return nil
	}
	left, err := a.rc.KeyCount(a.auth())
	if err != nil {
		return err
	}
	spk := a.v.LatestSPK()
	rotate := spk == nil || now.Sub(time.Unix(spk.Created, 0)) > spkMaxAge
	n := 0
	if left < otpkLow {
		n = otpkBatch
	}
	if rotate || n > 0 {
		if err := a.publishPreKeys(rotate, n); err != nil {
			return err
		}
	}
	// A device list the relay may not have yet (an approve or unlink whose
	// upload failed) goes out now.
	uploaded := false
	if a.v.ListNeedsUpload() {
		uploaded = a.rc.SetDevices(a.auth(), a.v.OwnDevices()) == nil
	}
	ignored, ierr := a.rc.Ignored(a.auth())
	return a.v.Update(func() error {
		a.v.SetKeyCheck(now.Unix())
		if uploaded {
			a.v.SetListUploaded(true)
		}
		if ierr == nil {
			a.v.SetIgnoreList(ignored)
		}
		return nil
	})
}
