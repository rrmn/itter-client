package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/rrmn/itter-client/internal/pqc"
)

// TestStoreConformance runs the same checks against every Store.
//
// The in-memory store always runs. To check the PostgREST store against a
// real Supabase project (do this once before deploying the relay), apply
// supabase/dm_relay.sql and run:
//
//	ITTER_TEST_POSTGREST_URL=https://<project>.supabase.co/rest/v1 \
//	ITTER_TEST_POSTGREST_KEY=<service role key> \
//	go test ./internal/server -run TestStoreConformance -v
//
// It creates two throwaway rows in public.users (dmtest_<random>) and deletes
// them again; it touches no existing account.
func TestStoreConformance(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		ms := NewMemStore()
		ms.AddUser("DmTest_Ab1", testSSHKey)
		ms.AddUser("dmtestxab1")
		conformance(t, ms, "DmTest_Ab1", "dmtestxab1")
	})
	t.Run("postgrest", func(t *testing.T) {
		url, key := os.Getenv("ITTER_TEST_POSTGREST_URL"), os.Getenv("ITTER_TEST_POSTGREST_KEY")
		if url == "" || key == "" {
			t.Skip("ITTER_TEST_POSTGREST_URL / ITTER_TEST_POSTGREST_KEY not set")
		}
		st := NewPostgRESTStore(url, key)
		rnd := make([]byte, 3)
		rand.Read(rnd)
		a, b := "DmTest_"+hex.EncodeToString(rnd), "dmtestx"+hex.EncodeToString(rnd)
		// One cleanup for both users, in an order that works whatever the
		// test left behind: what refers to the users first, the users last.
		// Whatever cannot be removed is reported, so that it can be done by hand.
		var ids []string
		t.Cleanup(func() {
			for _, id := range ids {
				_ = st.DeleteIdentity(id)
				for _, path := range []string{"/ignored_users?ignorer_id=eq.", "/ignored_users?ignored_user_id=eq.", "/user_public_keys?user_id=eq."} {
					if err := st.req("DELETE", path+q(id), nil, "return=minimal", nil); err != nil {
						t.Errorf("cleanup %s%s: %v", path, id, err)
					}
				}
			}
			for _, id := range ids {
				if err := st.req("DELETE", "/users?id=eq."+q(id), nil, "return=minimal", nil); err != nil {
					t.Errorf("cleanup: test user %s is still there: %v", id, err)
				}
			}
		})
		for _, name := range []string{a, b} {
			var rows []struct {
				ID string `json:"id"`
			}
			// itter's users table still requires the (legacy) public_key column:
			// a gets its one key there too, b a key of its own.
			legacy := testSSHKey
			if name != a {
				legacy = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== " + name
			}
			row := map[string]string{"username": name, "public_key": legacy}
			if err := st.req("POST", "/users?select=id", row, "return=representation", &rows); err != nil || len(rows) != 1 {
				t.Fatalf("create test user %s: %v", name, err)
			}
			id := rows[0].ID
			ids = append(ids, id)
			if name == a {
				row := map[string]string{"user_id": id, "name": "dmtest", "public_key": testSSHKey}
				if err := st.req("POST", "/user_public_keys", row, "return=minimal", nil); err != nil {
					t.Fatalf("add test key: %v", err)
				}
			}
		}
		conformance(t, st, a, b)
	})
}

const testSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== test"

func prekey(id uint32) *pqc.PreKeyPublic {
	return &pqc.PreKeyPublic{ID: id, DH: bytes.Repeat([]byte{1}, 32), MLKEM: []byte("mlkem"), Frodo: []byte("frodo")}
}

// conformance expects two existing users: a (mixed case, with an underscore
// and one SSH key) and b (which differs from a only where a has the underscore).
func conformance(t *testing.T, st Store, a, b string) {
	ua, err := st.User(a)
	if err != nil || ua.Name != a || ua.ID == "" {
		t.Fatalf("User(%q) = %+v, %v", a, ua, err)
	}
	if u, err := st.User(string(bytes.ToLower([]byte(a)))); err != nil || u != ua {
		t.Fatalf("lookup must ignore case and return itter's spelling: %+v, %v", u, err)
	}
	ub, err := st.User(b)
	if err != nil || ub.ID == ua.ID {
		t.Fatalf("User(%q) = %+v, %v ('_' must not act as a wildcard)", b, ub, err)
	}
	if _, err := st.User("no_such_user_x"); err != errNotFound {
		t.Fatalf("unknown user: %v", err)
	}
	// Keys come from user_public_keys and, for accounts from before itter had
	// several keys, from users.public_key: the same key may be listed twice.
	keys, err := st.SSHKeys(ua.ID)
	if err != nil || len(keys) == 0 {
		t.Fatalf("SSHKeys = %v, %v", keys, err)
	}
	for _, k := range keys {
		if k != testSSHKey {
			t.Fatalf("SSHKeys = %v: not only the test key", keys)
		}
	}

	// identities: first writer wins, and the first device comes with it
	if rec, err := st.Identity(ua.ID); err != nil || rec != nil {
		t.Fatalf("fresh account has an identity: %+v, %v", rec, err)
	}
	if id, devs, err := st.DeviceIDs(ua.ID); err != nil || id != "" || len(devs) != 0 {
		t.Fatalf("DeviceIDs = %q, %v, %v", id, devs, err)
	}
	const d0, d1, d2 = "id-one", "dev-one", "dev-two"
	first := &IdentityRecord{Identity: []byte("identity one \x00\xff"), ID: d0, RecoveryKey: bytes.Repeat([]byte{7}, 64)}
	if ok, err := st.CreateIdentity(ua, first); err != nil || !ok {
		t.Fatalf("CreateIdentity = %v, %v", ok, err)
	}
	if ok, err := st.CreateIdentity(ua, &IdentityRecord{Identity: []byte("two"), ID: "id-two", RecoveryKey: []byte("h")}); err != nil || ok {
		t.Fatalf("a second identity replaced the first: %v, %v", ok, err)
	}
	rec, err := st.Identity(ua.ID)
	if err != nil || rec == nil || !bytes.Equal(rec.Identity, first.Identity) || rec.ID != d0 ||
		!bytes.Equal(rec.RecoveryKey, first.RecoveryKey) || rec.ListV != 0 || len(rec.List) != 0 {
		t.Fatalf("Identity = %+v, %v", rec, err)
	}
	devs, err := st.Devices(ua.ID)
	if err != nil || len(devs) != 1 || devs[0].ID != d0 || !devs[0].Primary || !bytes.Equal(devs[0].Key, first.Identity) {
		t.Fatalf("Devices = %+v, %v", devs, err)
	}

	// device list: only newer versions, and the linked devices follow it
	list1, list2 := []byte(`{"v":1,"keys":["a","b"]}`), []byte(`{"v":2,"keys":["b"]}`)
	linked := []Device{{ID: d1, Key: []byte("key one \x00")}, {ID: d2, Key: []byte("key two")}}
	if ok, err := st.SetDeviceList(ua.ID, 1, list1, linked); err != nil || !ok {
		t.Fatalf("SetDeviceList v1 = %v, %v", ok, err)
	}
	if ok, err := st.SetDeviceList(ua.ID, 1, []byte(`{}`), nil); err != nil || ok {
		t.Fatalf("the same version was accepted twice: %v, %v", ok, err)
	}
	rec, _ = st.Identity(ua.ID)
	if rec.ListV != 1 || !bytes.Equal(rec.List, list1) {
		t.Fatalf("stored list = v%d %q", rec.ListV, rec.List)
	}
	devs, _ = st.Devices(ua.ID)
	if len(devs) != 3 || !devs[0].Primary || devs[1].Primary || !bytes.Equal(devs[1].Key, linked[0].Key) && !bytes.Equal(devs[2].Key, linked[0].Key) {
		t.Fatalf("Devices after linking = %+v", devs)
	}
	if id, ids, err := st.DeviceIDs(ua.ID); err != nil || id != d0 || len(ids) != 3 {
		t.Fatalf("DeviceIDs = %q, %v, %v", id, ids, err)
	}

	// prekeys, per device
	if spks, err := st.SignedPreKeys(ua.ID); err != nil || len(spks) != 0 {
		t.Fatalf("signed prekeys before upload: %v, %v", spks, err)
	}
	if err := st.PutPreKeys(ua.ID, d0, prekey(1), []byte("sig1"), []*pqc.PreKeyPublic{prekey(10), prekey(11)}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPreKeys(ua.ID, d0, prekey(2), []byte("sig2"), []*pqc.PreKeyPublic{prekey(11), prekey(12)}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPreKeys(ua.ID, d1, prekey(5), []byte("sig5"), []*pqc.PreKeyPublic{prekey(10)}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPreKeys(ua.ID, "no-such-device", prekey(9), []byte("x"), nil); err == nil {
		t.Fatal("prekeys were stored for a device the account does not have")
	}
	spks, err := st.SignedPreKeys(ua.ID)
	if err != nil || len(spks) != 2 || spks[d0].Key.ID != 2 || string(spks[d0].Sig) != "sig2" ||
		!bytes.Equal(spks[d0].Key.DH, prekey(2).DH) || spks[d1].Key.ID != 5 {
		t.Fatalf("SignedPreKeys = %+v, %v", spks, err)
	}
	if n, err := st.CountOTPKs(ua.ID, d0); err != nil || n != 3 {
		t.Fatalf("CountOTPKs = %d, %v (a re-uploaded one-time prekey must not be stored twice)", n, err)
	}
	seen := map[uint32]bool{}
	for i := 0; i < 3; i++ {
		k, err := st.ClaimOTPK(ua.ID, d0)
		if err != nil || k == nil || seen[k.ID] || string(k.MLKEM) != "mlkem" {
			t.Fatalf("claim %d: %+v, %v", i, k, err)
		}
		seen[k.ID] = true
	}
	if k, err := st.ClaimOTPK(ua.ID, d0); err != nil || k != nil {
		t.Fatalf("claim from an empty stock: %+v, %v", k, err)
	}
	if n, _ := st.CountOTPKs(ua.ID, d1); n != 1 {
		t.Fatalf("one device's claims used up another device's prekeys: %d left", n)
	}

	// inbox, per device
	msg := func(i int) []byte {
		b, _ := json.Marshal(pqc.WireMsg{Type: 2, From: b, Payload: json.RawMessage(`{"v":2,"n":` + string(rune('0'+i)) + `}`)})
		return b
	}
	for i := 0; i < 3; i++ {
		msgs := map[string][]byte{d0: msg(i)}
		if i == 0 {
			msgs[d1] = msg(i)
		}
		if ok, err := st.PutMessages(ua.ID, b, msgs, 3); err != nil || !ok {
			t.Fatalf("PutMessages %d = %v, %v", i, ok, err)
		}
	}
	// d0 has no room for this sender any more, d1 has: a device that is away
	// must not keep the others from getting their copy.
	for i := 3; i < 5; i++ {
		if ok, err := st.PutMessages(ua.ID, b, map[string][]byte{d0: msg(i), d1: msg(i)}, 3); err != nil || !ok {
			t.Fatalf("a full device kept a message from the other one: %v, %v", ok, err)
		}
	}
	if s, _ := st.Senders(ua.ID, d0); s[b] != 3 {
		t.Fatalf("the per-sender limit was not enforced: %v", s)
	}
	if s, _ := st.Senders(ua.ID, d1); s[b] != 3 {
		t.Fatalf("the device with room did not get its copies: %v", s)
	}
	// Only when no device can take it is the sender told to keep it.
	if ok, err := st.PutMessages(ua.ID, b, map[string][]byte{d0: msg(5), d1: msg(5)}, 3); err != nil || ok {
		t.Fatalf("a message nobody had room for was reported as stored: %v, %v", ok, err)
	}
	if s, _ := st.Senders(ua.ID, d1); s[b] != 3 {
		t.Fatalf("a refused batch was stored in part: %v", s)
	}
	if ok, err := st.PutMessages(ua.ID, "someoneelse", map[string][]byte{d0: msg(4)}, 3); err != nil || !ok {
		t.Fatalf("the limit must be per sender: %v, %v", ok, err)
	}
	if ok, err := st.PutMessages(ua.ID, b, map[string][]byte{"no-such-device": msg(6)}, 3); err == nil && ok {
		t.Fatal("a message was stored for a device the account does not have")
	}
	senders, err := st.Senders(ua.ID, d0)
	if err != nil || senders[b] != 3 || senders["someoneelse"] != 1 || len(senders) != 2 {
		t.Fatalf("Senders = %v, %v", senders, err)
	}
	if s, err := st.Senders(ua.ID, d2); err != nil || len(s) != 0 {
		t.Fatalf("Senders of an empty inbox = %v, %v", s, err)
	}
	two, err := st.Messages(ua.ID, d0, b, 2)
	if err != nil || len(two) != 2 || two[0].ID >= two[1].ID {
		t.Fatalf("Messages(limit 2) = %+v, %v", two, err)
	}
	var w pqc.WireMsg
	if err := json.Unmarshal(two[0].Payload, &w); err != nil || w.From != b || w.Type != 2 {
		t.Fatalf("payload did not survive storage: %s", two[0].Payload)
	}
	all, _ := st.Messages(ua.ID, d0, b, 50)
	if len(all) != 3 {
		t.Fatalf("fetching must not delete: %d left", len(all))
	}
	if err := st.Ack(ub.ID, d0, []int64{all[0].ID}); err != nil { // someone else's ack
		t.Fatal(err)
	}
	if err := st.Ack(ua.ID, d1, []int64{all[0].ID}); err != nil { // another device's ack
		t.Fatal(err)
	}
	if left, _ := st.Messages(ua.ID, d0, b, 50); len(left) != 3 {
		t.Fatal("a message was acknowledged (deleted) by someone it was not for")
	}
	if err := st.Ack(ua.ID, d0, []int64{all[0].ID, all[1].ID}); err != nil {
		t.Fatal(err)
	}
	if left, _ := st.Messages(ua.ID, d0, b, 50); len(left) != 1 || left[0].ID != all[2].ID {
		t.Fatalf("after ack: %+v", left)
	}

	// ignore list: one-way, and ignoring drops what the other has waiting
	if ok, err := st.Ignores(ua.ID, ub.ID); err != nil || ok {
		t.Fatalf("Ignores before = %v, %v", ok, err)
	}
	if err := st.SetIgnore(ua, ub, true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetIgnore(ua, ub, true); err != nil {
		t.Fatalf("ignoring twice: %v", err)
	}
	if ok, _ := st.Ignores(ua.ID, ub.ID); !ok {
		t.Fatal("not ignored after SetIgnore")
	}
	if ok, _ := st.Ignores(ub.ID, ua.ID); ok {
		t.Fatal("ignoring must be one-way")
	}
	if names, err := st.Ignored(ua.ID); err != nil || len(names) != 1 || names[0] != b {
		t.Fatalf("Ignored = %v, %v", names, err)
	}
	if s, _ := st.Senders(ua.ID, d0); s[b] != 0 || s["someoneelse"] != 1 {
		t.Fatalf("ignoring must drop that sender's waiting messages, and only those: %v", s)
	}
	if s, _ := st.Senders(ua.ID, d1); s[b] != 0 {
		t.Fatalf("...on every device: %v", s)
	}
	if err := st.SetIgnore(ua, ub, false); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.Ignores(ua.ID, ub.ID); ok {
		t.Fatal("still ignored after unignore")
	}
	if names, _ := st.Ignored(ua.ID); len(names) != 0 {
		t.Fatalf("Ignored after unignore = %v", names)
	}

	// link requests
	l := &Link{ID: "link-1", DeviceKey: []byte("new device \x00"), Tag: []byte("tag")}
	if ok, err := st.PutLink(ua.ID, l, 2); err != nil || !ok {
		t.Fatalf("PutLink = %v, %v", ok, err)
	}
	if ok, _ := st.PutLink(ua.ID, &Link{ID: "link-2", DeviceKey: []byte("k"), Tag: []byte("t")}, 2); !ok {
		t.Fatal("second link request refused")
	}
	if ok, err := st.PutLink(ua.ID, &Link{ID: "link-3", DeviceKey: []byte("k"), Tag: []byte("t")}, 2); err != nil || ok {
		t.Fatalf("more link requests than allowed: %v, %v", ok, err)
	}
	if ok, _ := st.PutLink(ua.ID, l, 2); !ok {
		t.Fatal("the same request again must be fine")
	}
	got, err := st.Link(ua.ID, "link-1")
	if err != nil || got == nil || !bytes.Equal(got.DeviceKey, l.DeviceKey) || !bytes.Equal(got.Tag, l.Tag) || len(got.Result) != 0 {
		t.Fatalf("Link = %+v, %v", got, err)
	}
	if other, _ := st.Link(ub.ID, "link-1"); other != nil {
		t.Fatal("a link request is visible under another account")
	}
	if err := st.SetLinkResult(ua.ID, "link-1", []byte("the answer \x00")); err != nil {
		t.Fatal(err)
	}
	if err := st.SetLinkResult(ua.ID, "no-such-link", []byte("x")); err == nil {
		t.Fatal("answered a link request that does not exist")
	}
	if got, _ := st.Link(ua.ID, "link-1"); got == nil || string(got.Result) != "the answer \x00" {
		t.Fatalf("answer not stored: %+v", got)
	}

	// taking a device off the list removes what hung off it; the rest stays
	_, _ = st.PutMessages(ua.ID, b, map[string][]byte{d0: msg(7), d1: msg(7)}, 9)
	if ok, err := st.SetDeviceList(ua.ID, 2, list2, linked[1:]); err != nil || !ok {
		t.Fatalf("SetDeviceList v2 = %v, %v", ok, err)
	}
	devs, _ = st.Devices(ua.ID)
	if len(devs) != 2 || devs[1].ID != d2 {
		t.Fatalf("Devices after unlinking = %+v", devs)
	}
	spks, _ = st.SignedPreKeys(ua.ID)
	if _, still := spks[d1]; still || len(spks) != 1 {
		t.Fatalf("prekeys of a removed device survived: %v", spks)
	}
	if s, _ := st.Senders(ua.ID, d1); len(s) != 0 {
		t.Fatal("inbox of a removed device survived")
	}
	if s, _ := st.Senders(ua.ID, d0); s[b] == 0 {
		t.Fatal("removing one device emptied another device's inbox")
	}
	// retiring a device empties it but keeps it listed
	if err := st.ClearDevice(ua.ID, d0); err != nil {
		t.Fatal(err)
	}
	if spks, _ := st.SignedPreKeys(ua.ID); len(spks) != 0 {
		t.Fatalf("prekeys survived ClearDevice: %v", spks)
	}
	if s, _ := st.Senders(ua.ID, d0); len(s) != 0 {
		t.Fatal("inbox survived ClearDevice")
	}
	if devs, _ := st.Devices(ua.ID); len(devs) != 2 {
		t.Fatal("ClearDevice must not unlist the device")
	}

	// release removes everything that depended on the identity
	_ = st.PutPreKeys(ua.ID, d0, prekey(3), []byte("sig3"), []*pqc.PreKeyPublic{prekey(20)})
	_, _ = st.PutMessages(ua.ID, b, map[string][]byte{d0: msg(8)}, 9)
	if err := st.DeleteIdentity(ua.ID); err != nil {
		t.Fatal(err)
	}
	if rec, _ := st.Identity(ua.ID); rec != nil {
		t.Fatal("identity survived the release")
	}
	if devs, _ := st.Devices(ua.ID); len(devs) != 0 {
		t.Fatal("devices survived the release")
	}
	if spks, _ := st.SignedPreKeys(ua.ID); len(spks) != 0 {
		t.Fatal("signed prekeys survived the release")
	}
	if s, _ := st.Senders(ua.ID, d0); len(s) != 0 {
		t.Fatal("inbox survived the release")
	}
	if got, _ := st.Link(ua.ID, "link-1"); got != nil {
		t.Fatal("link requests survived the release")
	}
	if ok, err := st.CreateIdentity(ua, &IdentityRecord{Identity: []byte("two"), ID: "id-two", RecoveryKey: []byte("h")}); err != nil || !ok {
		t.Fatalf("after a release the account must be free: %v, %v", ok, err)
	}
	if rec, _ := st.Identity(ua.ID); rec == nil || rec.ListV != 0 {
		t.Fatal("a new identity must start without a device list")
	}
	_ = st.DeleteIdentity(ua.ID)
}
