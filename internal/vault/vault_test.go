package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"itter-cli/internal/pqc"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

// One vault for all tests that just need "a vault" (identities are slow).
var (
	baseOnce sync.Once
	baseDir  string
)

func newVault(t *testing.T) *Vault {
	t.Helper()
	baseOnce.Do(func() {
		baseDir = filepath.Join(os.TempDir(), "itter-vault-test-"+newID())
		if _, err := Create(baseDir, "alice"); err != nil {
			t.Fatal(err)
		}
	})
	// Copy it, with its own keychain entry.
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{fileName, usernameFile} {
		b, err := os.ReadFile(filepath.Join(baseDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	key, err := keyring.Get(serviceName, accountFor(baseDir, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	account := "alice@" + newID()
	if err := keyring.Set(serviceName, account, key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, vaultIDFile), []byte(account), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func fakeIdentity(b byte) []byte { return append([]byte("identity-"), b) }

func fakeSession(identity []byte, hs byte) *pqc.Session {
	return &pqc.Session{V: pqc.ProtocolVersion, TheirIdentity: identity, HandshakeID: []byte{hs},
		DR: &pqc.DR{}, PQ1: &pqc.Braid{}, PQ2: &pqc.Braid{}, PQ1Chain: &pqc.PQChain{}, PQ2Chain: &pqc.PQChain{}}
}

func TestCreateOpenAndRecoveryCode(t *testing.T) {
	v := newVault(t)
	me, id := v.Me()
	if me != "alice" || !id.Valid() {
		t.Fatal("identity not loaded")
	}
	var code []byte
	if err := v.Update(func() (err error) { code, err = v.RecoveryCode(); return }); err != nil {
		t.Fatal(err)
	}
	if len(code) != 32 {
		t.Fatal("no recovery code")
	}
	v2, err := Open(v.Dir())
	if err != nil {
		t.Fatal(err)
	}
	var again []byte
	_ = v2.Update(func() (err error) { again, err = v2.RecoveryCode(); return })
	if string(again) != string(code) {
		t.Fatal("recovery code changed between runs")
	}
}

// Two itter processes on one state directory must never work from stale
// ratchet state: each Update sees what the other wrote.
func TestTwoProcessesShareOneVault(t *testing.T) {
	shell := newVault(t)
	oneShot, err := Open(shell.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if err := oneShot.Update(func() error {
		oneShot.AddMessage("bob", ChatMsg{ID: "1", Text: "from the second terminal"})
		oneShot.ReservePreKeyIDs(5)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var seen int
	var next uint32
	if err := shell.Update(func() error {
		seen = len(shell.GetMessages("bob"))
		next = shell.ReservePreKeyIDs(1)
		shell.AddMessage("bob", ChatMsg{ID: "2", Text: "from the shell"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 || next != 6 {
		t.Fatalf("the shell worked from stale state: saw %d message(s), next prekey id %d", seen, next)
	}
	if err := oneShot.Refresh(); err != nil {
		t.Fatal(err)
	}
	if got := len(oneShot.GetMessages("bob")); got != 2 {
		t.Fatalf("after refresh: %d messages, want 2", got)
	}

	// Hammer it from both sides.
	var wg sync.WaitGroup
	for _, v := range []*Vault{shell, oneShot} {
		wg.Add(1)
		go func(v *Vault) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				_ = v.Update(func() error { v.ReservePreKeyIDs(1); return nil })
			}
		}(v)
	}
	wg.Wait()
	_ = shell.Update(func() error { next = shell.ReservePreKeyIDs(1); return nil })
	if next != 7+80 {
		t.Fatalf("lost updates: next prekey id %d, want %d", next, 87)
	}
}

func TestTrustOnFirstUseAndIdentityChange(t *testing.T) {
	v := newVault(t)
	idA, idB, idC := fakeIdentity('A'), fakeIdentity('B'), fakeIdentity('C')
	err := v.Update(func() error {
		if st := v.Observe("bob", idA); st != IdentityNew {
			t.Errorf("first contact: %v", st)
		}
		if st := v.Observe("bob", idA); st != IdentityKnown {
			t.Errorf("same identity: %v", st)
		}
		if err := v.InstallSession("bob", fakeSession(idA, 1)); err != nil {
			t.Error(err)
		}
		if err := v.InstallSession("bob", fakeSession(idA, 2)); err != nil { // crossing handshake
			t.Error(err)
		}
		if err := v.InstallSession("bob", fakeSession(idB, 3)); err == nil {
			t.Error("a session for a different identity must not be installable")
		}

		// An identity never changes under the user, verified or not: a
		// different one is only a candidate, and the sessions stay as they are.
		if st := v.Observe("bob", idB); st != IdentityBlocked {
			t.Errorf("change: %v", st)
		}
		if !v.HasSession("bob") || !v.KnownHandshake("bob", []byte{1}) {
			t.Error("a pending identity must leave the existing sessions alone")
		}
		if info, _ := v.ContactInfo("bob"); string(info.Identity) != string(idA) || string(info.Pending) != string(idB) {
			t.Error("the identity on record changed without the user")
		}
		if !v.Announce("bob") || v.Announce("bob") {
			t.Error("a pending identity is announced exactly once")
		}
		// A third identity replaces the candidate (and is news again).
		if err := v.SetVerified("bob", true); err != nil {
			t.Error(err)
		}
		v.Hold("bob", []byte("for B"))
		if st := v.Observe("bob", idC); st != IdentityBlocked {
			t.Errorf("verified change: %v", st)
		}
		if info, _ := v.ContactInfo("bob"); info.Held != 0 || info.Announced {
			t.Errorf("messages held for an older candidate must not carry over: %+v", info)
		}
		if !v.Announce("bob") {
			t.Error("a different candidate must be announced again")
		}
		for i := 0; i < maxHeld+3; i++ {
			v.Hold("bob", []byte("msg"))
		}
		info, _ := v.ContactInfo("bob")
		if info.Held != maxHeld || !info.Verified || string(info.Pending) != string(idC) {
			t.Errorf("held=%d verified=%v", info.Held, info.Verified)
		}
		held, err := v.Accept("bob")
		if err != nil || len(held) != maxHeld {
			t.Errorf("accept: %d held, %v", len(held), err)
		}
		info, _ = v.ContactInfo("bob")
		if info.Verified || string(info.Identity) != string(idC) || v.HasSession("bob") {
			t.Error("after accept: must be the new identity, unverified, old sessions gone")
		}
		if _, err := v.Accept("bob"); err == nil {
			t.Error("nothing left to accept")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProposedIdentities(t *testing.T) {
	v := newVault(t)
	idA, idB := fakeIdentity('A'), fakeIdentity('B')
	err := v.Update(func() error {
		// A stranger's identity is only proposed: no contact, nothing to verify.
		v.Propose("eve", idA)
		if _, known := v.ContactInfo("eve"); known {
			t.Error("a proposed identity made a contact")
		}
		if v.SetVerified("eve", true) == nil {
			t.Error("a proposed identity could be verified")
		}
		if err := v.InstallSession("eve", fakeSession(idA, 1)); err == nil {
			t.Error("a session could be installed for an identity that was only proposed")
		}
		if n, ok := v.Hold("eve", []byte("m1")); n != 1 || !ok {
			t.Errorf("hold: %d %v", n, ok)
		}
		if n := v.DropPending("eve"); n != 1 {
			t.Errorf("dropped %d", n)
		}
		if len(v.ContactList()) != 0 {
			t.Error("a dropped stranger left a contact behind")
		}

		// For a known contact, dropping the candidate leaves the contact intact.
		v.Observe("bob", idA)
		_ = v.SetVerified("bob", true)
		v.Propose("bob", idB)
		v.Hold("bob", []byte("m"))
		v.DropPending("bob")
		info, known := v.ContactInfo("bob")
		if !known || !info.Verified || len(info.Pending) != 0 || info.Held != 0 || string(info.Identity) != string(idA) {
			t.Errorf("after dropping the candidate: %+v", info)
		}

		// Alerts are rate-limited per contact.
		if !v.AlertDue("bob") || v.AlertDue("bob") {
			t.Error("alerts must be rate-limited")
		}
		if !v.AlertDue("carol") {
			t.Error("the limit is per contact")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeMemoryIsPerContact(t *testing.T) {
	v := newVault(t)
	err := v.Update(func() error {
		v.Observe("bob", fakeIdentity('B'))
		v.Observe("mallory", fakeIdentity('M'))
		v.MarkHandshake("bob", []byte{1})
		for i := 0; i < 3*maxSeenHandshakes; i++ { // mallory floods her own memory only
			v.MarkHandshake("mallory", []byte{2, byte(i), byte(i >> 8)})
		}
		if !v.HandshakeSeen("bob", []byte{1}) {
			t.Error("another contact's handshakes pushed bob's out of memory")
		}
		if v.HandshakeSeen("mallory", []byte{1}) || v.HandshakeSeen("nobody", []byte{1}) {
			t.Error("handshake memory leaked across contacts")
		}
		last := 3*maxSeenHandshakes - 1
		if !v.HandshakeSeen("mallory", []byte{2, byte(last), byte(last >> 8)}) || v.HandshakeSeen("mallory", []byte{2, 0, 0}) {
			t.Error("the memory must keep the most recent handshakes and stay bounded")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadMarkers(t *testing.T) {
	v := newVault(t)
	err := v.Update(func() error {
		for i := 0; i < 3; i++ {
			v.AddMessage("bob", ChatMsg{ID: string(rune('a' + i)), Text: "m"})
		}
		v.MarkRead(map[string]int{"bob": 2, "ghost": 5})
		v.MarkRead(map[string]int{"bob": 1}) // never backwards
		v.MarkRead(map[string]int{"bob": 99})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := Open(v.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if got := v2.ReadCounts(); got["bob"] != 3 || got["ghost"] != 0 {
		t.Fatalf("read markers after reopen: %v", got)
	}
}

func TestWireDedupeAndTimestamps(t *testing.T) {
	v := newVault(t)
	_ = v.Update(func() error {
		if !v.FirstTime("a") || v.FirstTime("a") || !v.FirstTime("b") {
			t.Error("dedupe ring is wrong")
		}
		for i := 0; i < maxSeenWire+10; i++ {
			v.FirstTime(newID())
		}
		if len(v.SeenWire) != maxSeenWire {
			t.Errorf("ring not bounded: %d", len(v.SeenWire))
		}
		now := time.Now().Unix()
		v.AddMessage("bob", ChatMsg{TS: now - 100})
		if ts := v.IncomingTS("bob", now+99999); ts > now+1 {
			t.Error("a timestamp from the future was accepted")
		}
		if ts := v.IncomingTS("bob", 5); ts != now-100 {
			t.Error("a message could be slipped in before earlier history")
		}
		if ts := v.IncomingTS("bob", now-50); ts != now-50 {
			t.Error("a plausible timestamp was changed")
		}
		return nil
	})
}

func TestOutbox(t *testing.T) {
	v := newVault(t)
	_ = v.Update(func() error {
		for _, id := range []string{"1", "2", "3"} {
			v.AddMessage("bob", ChatMsg{ID: id, IsOut: true})
			v.QueueBatch(QueuedWire{ID: id, Target: "bob", ToID: "idid", Wires: map[string][]byte{"d1": []byte("w" + id)}})
		}
		v.AddMessage("carol", ChatMsg{ID: "9", IsOut: true})
		v.QueueBatch(QueuedWire{ID: "9", Target: "carol", ToID: "idid", Wires: map[string][]byte{"d1": []byte("w9")}, Payload: []byte("plain")})
		v.EditOutbox("9", func(q *QueuedWire) { q.Wires["d2"] = []byte("for a device linked meanwhile") })
		return nil
	})
	v2, _ := Open(v.Dir())
	if q := v2.OutboxSnapshot(); len(q) != 4 || q[0].ID != "1" || q[3].Target != "carol" || len(q[3].Wires) != 2 || string(q[3].Payload) != "plain" {
		t.Fatalf("outbox did not survive a restart in order: %+v", q)
	}
	_ = v2.Update(func() error {
		v2.RemoveOutbox("1")
		v2.SetStatus("bob", "1", StatusSent)
		if n := v2.FailOutboxFor("bob"); n != 2 {
			t.Errorf("failed %d, want 2", n)
		}
		return nil
	})
	msgs := v2.GetMessages("bob")
	if msgs[0].Status != StatusSent || msgs[1].Status != StatusFailed || msgs[2].Status != StatusFailed {
		t.Fatalf("statuses: %+v", msgs)
	}
	if q := v2.OutboxSnapshot(); len(q) != 1 || q[0].Target != "carol" {
		t.Fatalf("outbox: %+v", q)
	}
}

func TestLegacyAndBurn(t *testing.T) {
	v := newVault(t)
	dir := v.Dir()
	// A pre-v2 vault: identity in the old shape.
	v.Identity = &pqc.Identity{}
	if err := v.Update(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	old, err := Open(dir)
	if err != ErrLegacy || old == nil {
		t.Fatalf("got %v, want ErrLegacy with the vault", err)
	}
	if err := old.Burn(); err != nil {
		t.Fatal(err)
	}
	if Exists(dir) {
		t.Fatal("vault file still there after burn")
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("opened a burned vault")
	}
}

func TestKeychainEntrySurvivesRename(t *testing.T) {
	v := newVault(t)
	if err := v.Update(func() error { return v.SetUsername("Alice") }); err != nil {
		t.Fatal(err)
	}
	v2, err := Open(v.Dir())
	if err != nil {
		t.Fatalf("renaming the account lost the vault key: %v", err)
	}
	if me, _ := v2.Me(); me != "Alice" {
		t.Fatalf("name %q", me)
	}
}

func TestKeyFileFallbackWithoutKeychain(t *testing.T) {
	// Keep the shared fixture's key: the keychain mock is about to be reset.
	newVault(t)
	baseAccount := accountFor(baseDir, "alice")
	baseKey, err := keyring.Get(serviceName, baseAccount)
	if err != nil {
		t.Fatal(err)
	}
	keyring.MockInitWithError(errors.New("no secret service"))
	defer func() {
		keyring.MockInit()
		_ = keyring.Set(serviceName, baseAccount, baseKey)
	}()

	dir := filepath.Join(t.TempDir(), "state")
	if _, err := Create(dir, "bob"); err == nil || !strings.Contains(err.Error(), KeyFileEnv) {
		t.Fatalf("without a keychain, the error should point to %s: %v", KeyFileEnv, err)
	}
	_ = os.RemoveAll(dir)

	t.Setenv(KeyFileEnv, "1")
	v, err := Create(dir, "bob")
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file missing or too open: %v %v", st, err)
	}
	_ = v.Update(func() error { v.AddMessage("x", ChatMsg{Text: "hi"}); return nil })

	t.Setenv(KeyFileEnv, "") // later runs find the key file by themselves
	v2, err := Open(dir)
	if err != nil || len(v2.GetMessages("x")) != 1 {
		t.Fatalf("reopen: %v", err)
	}
	if err := v2.Burn(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, keyFile)); err == nil {
		t.Fatal("burn left the key file behind")
	}
}

func TestSessionsArePerDevice(t *testing.T) {
	v := newVault(t)
	first, laptop, phone, stranger := fakeIdentity('A'), fakeIdentity('L'), fakeIdentity('P'), fakeIdentity('X')
	idFirst, idLaptop, idPhone := devID(first), devID(laptop), devID(phone)
	err := v.Update(func() error {
		v.Observe("bob", first)
		if err := v.InstallSession("bob", fakeSession(laptop, 1)); err == nil {
			t.Error("a session with a device that is not on the contact's list was installed")
		}
		if added, ok := v.SetDevices("bob", 1, [][]byte{laptop, phone}, []string{idFirst, idLaptop, idPhone}); !ok || added != 2 {
			t.Errorf("SetDevices: added %d, ok %v", added, ok)
		}
		for i, key := range [][]byte{first, laptop, phone} {
			if err := v.InstallSession("bob", fakeSession(key, byte(i+1))); err != nil {
				t.Error(err)
			}
		}
		if got := v.SessionDevices("bob"); len(got) != 3 {
			t.Errorf("sessions with %d devices, want 3", len(got))
		}
		if !v.ValidDevice("bob", phone) || v.ValidDevice("bob", stranger) || v.ValidDevice("nobody", first) {
			t.Error("ValidDevice is wrong")
		}
		if info, _ := v.ContactInfo("bob"); info.Devices != 3 || !info.HasSession {
			t.Errorf("contact info: %+v", info)
		}
		// A second session with the same device replaces the first, which is kept for late messages.
		_ = v.InstallSession("bob", fakeSession(phone, 9))
		if !v.KnownHandshake("bob", []byte{3}) || !v.KnownHandshake("bob", []byte{9}) {
			t.Error("the replaced session must still be known")
		}

		// An older list must not bring anything back or take anything away.
		if _, ok := v.SetDevices("bob", 0, nil, []string{idFirst}); ok {
			t.Error("an older device list was accepted")
		}
		if !v.ValidDevice("bob", laptop) {
			t.Error("a rollback removed a device")
		}
		// The phone is taken off the list: its sessions are gone, the others stay.
		if added, ok := v.SetDevices("bob", 2, [][]byte{laptop}, []string{idFirst, idLaptop}); !ok || added != 0 {
			t.Errorf("SetDevices v2: added %d, ok %v", added, ok)
		}
		if v.ValidDevice("bob", phone) || v.KnownHandshake("bob", []byte{3}) || v.KnownHandshake("bob", []byte{9}) {
			t.Error("a removed device kept its sessions")
		}
		if got := v.SessionDevices("bob"); len(got) != 2 {
			t.Errorf("sessions with %d devices after removal, want 2", len(got))
		}
		if _, ok := v.SetDevices("bob", 1, [][]byte{laptop, phone}, nil); ok || v.ValidDevice("bob", phone) {
			t.Error("replaying the old list brought the removed device back")
		}
		if got := v.Reach("bob"); len(got) != 2 {
			t.Errorf("reach = %v", got)
		}

		// Accepting a new identity starts over: no devices are known for it.
		v.Observe("bob", stranger)
		if _, err := v.Accept("bob"); err != nil {
			t.Error(err)
		}
		if v.ValidDevice("bob", laptop) || v.HasSession("bob") || len(v.Reach("bob")) != 0 {
			t.Error("devices of the old identity survived an identity change")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOwnDevicesAreNotAContact(t *testing.T) {
	v := newVault(t)
	_, id := v.Me()
	own := id.Pub.Encode()
	other, _ := pqc.GenerateIdentity()
	if v.IsLinked() || string(v.AccountIdentity()) != string(own) || v.DeviceID() != devID(own) {
		t.Fatal("a first device's key is the account identity")
	}
	err := v.Update(func() error {
		list, err := pqc.SignDeviceList(id, "alice", 1, [][]byte{other.Pub.Encode()})
		if err != nil {
			return err
		}
		v.SetOwnDevices(own, list, []string{devID(other.Pub.Encode())})
		if err := v.InstallSession("alice", fakeSession(other.Pub.Encode(), 1)); err != nil {
			t.Errorf("session with one's own other device: %v", err)
		}
		v.Observe("bob", fakeIdentity('B'))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := Open(v.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if l := v2.OwnDevices(); l.Version() != 1 || !l.Has(other.Pub.Encode()) {
		t.Fatal("own device list did not survive a restart")
	}
	if list := v2.ContactList(); len(list) != 1 || list[0].Name != "bob" {
		t.Fatalf("one's own account showed up as a contact: %+v", list)
	}
	if got := v2.SessionDevices("alice"); len(got) != 1 {
		t.Fatalf("own-device sessions: %v", got)
	}
}

func TestLinkedVault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "linked")
	v, err := CreateLinked(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Burn() })
	if !v.IsLinked() || len(v.AccountIdentity()) != 0 {
		t.Fatal("a linked device has no account identity until it is linked")
	}
	var c1, c2 []byte
	_ = v.Update(func() (err error) { c1, err = v.LinkCode(); return })
	v2, _ := Open(dir)
	_ = v2.Update(func() (err error) { c2, err = v2.LinkCode(); return })
	if len(c1) != pqc.LinkSecretSize || string(c1) != string(c2) {
		t.Fatal("the link code must be stable while the request is under way")
	}
	if err := v2.Update(func() (err error) { _, err = v2.RecoveryCode(); return }); err == nil {
		t.Fatal("a linked device has no recovery code: that belongs to the account identity")
	}
	account := fakeIdentity('R')
	_ = v2.Update(func() error { v2.SetOwnDevices(account, nil, nil); return nil })
	v3, _ := Open(dir)
	if string(v3.AccountIdentity()) != string(account) || len(v3.LinkSecret) != 0 {
		t.Fatal("after linking: the account identity is on record and the code is gone")
	}
}

func TestMigrationFromOneSessionPerContact(t *testing.T) {
	v := newVault(t)
	idB := fakeIdentity('B')
	_ = v.Update(func() error {
		// What a vault written before devices existed looks like.
		v.Contacts["bob"] = &Contact{Identity: idB, Verified: true}
		v.Sessions["bob"] = fakeSession(idB, 1)
		v.Previous["bob"] = []*pqc.Session{fakeSession(idB, 2)}
		v.Outbox = []QueuedWire{{ID: "m1", Target: "bob", ToID: devID(idB), Wire: []byte("old")}}
		return nil
	})
	v2, err := Open(v.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if !v2.HasSession("bob") || !v2.KnownHandshake("bob", []byte{1}) || !v2.KnownHandshake("bob", []byte{2}) {
		t.Fatal("sessions were lost in the migration")
	}
	if got := v2.Reach("bob"); len(got) != 1 || got[0] != devID(idB) {
		t.Fatalf("reach after migration: %v", got)
	}
	q := v2.OutboxSnapshot()
	if len(q) != 1 || string(q[0].Wires[devID(idB)]) != "old" {
		t.Fatalf("a queued message was lost in the migration: %+v", q)
	}
	if info, _ := v2.ContactInfo("bob"); !info.Verified {
		t.Fatal("the verified mark was lost")
	}
}
