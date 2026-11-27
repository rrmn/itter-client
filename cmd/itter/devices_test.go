package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"itter-cli/internal/api"
	"itter-cli/internal/pqc"
	"itter-cli/internal/relay"
	"itter-cli/internal/vault"
)

// second gives an account another device: its own state directory, the same
// SSH agent.
func (u *user) second(t *testing.T) *user {
	dir, err := os.MkdirTemp("", "itter-e2e-dev-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return &user{t: t, name: u.name, dir: filepath.Join(dir, "state"), sock: u.sock}
}

// link runs `itter link` on the new device and `itter approve` on the first,
// like a user with both in front of them.
func (w *world) link(t *testing.T, first, dev *user) {
	t.Helper()
	w.linkWith(t, first, dev, func(code []byte) error {
		_, err := first.app().approve(code)
		return err
	})
}

// linkWith is link with the approval done by approve, which is tried again
// while it reports that no device is waiting (the request is on its way).
func (w *world) linkWith(t *testing.T, first, dev *user, approve func(code []byte) error) {
	t.Helper()
	old := linkPoll
	linkPoll = 300 * time.Millisecond // well under the relay's limit for requests without a login
	defer func() { linkPoll = old }()
	first.use() // both devices share the SSH agent
	done := make(chan error, 1)
	rc := relay.New(w.ts.URL) // given, not looked up: the environment belongs to the whole process
	go func() { done <- linkDevice(dev.dir, rc, dev.name) }()

	// The new device shows a code; the user types it into the first device.
	var secret []byte
	deadline := time.Now().Add(20 * time.Second)
	for len(secret) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the new device never showed a link code")
		}
		time.Sleep(20 * time.Millisecond)
		if v, err := vault.Open(dev.dir); err == nil {
			secret = v.LinkSecret
		}
	}
	for {
		err := approve(secret)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "no device is waiting") || time.Now().After(deadline) {
			t.Fatalf("approve: %v", err)
		}
		time.Sleep(20 * time.Millisecond) // the request is still on its way to the relay
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("link: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the new device did not finish linking")
	}
}

// sent returns the texts of the messages u's device shows as sent to peer.
func (u *user) sent(peer string) []string {
	var out []string
	for _, m := range u.app().v.GetMessages(peer) {
		if m.IsOut && !m.IsSystem {
			out = append(out, m.Text)
		}
	}
	return out
}

func TestLinkedDevices(t *testing.T) {
	w := newWorld(t)
	alice, bob := w.ready(t, "alice"), w.ready(t, "bob")
	alice.mustSend("bob", "before the laptop")
	expectTexts(t, bob.pull("alice"), "before the laptop")
	bob.mustSend("alice", "ok")
	expectTexts(t, alice.pull("bob"), "ok")
	sn := bob.app().safetyNumber(alice.app().v.AccountIdentity())

	laptop := alice.second(t)

	t.Run("a wrong code links nothing", func(t *testing.T) {
		_, err := alice.app().approve(make([]byte, pqc.LinkSecretSize))
		if err == nil || !strings.Contains(err.Error(), "no device is waiting") {
			t.Fatalf("approve with a code nobody showed: %v", err)
		}
	})

	t.Run("link and approve", func(t *testing.T) {
		w.link(t, alice, laptop)
		l := laptop.app()
		if !l.v.IsLinked() || !pqc.IdentityEqual(l.v.AccountIdentity(), alice.app().v.AccountIdentity()) {
			t.Fatal("the linked device does not know the account identity")
		}
		if l.v.DeviceID() == alice.app().v.DeviceID() {
			t.Fatal("the linked device must have a key of its own")
		}
		_, lid := l.v.Me()
		_, aid := alice.app().v.Me()
		if string(lid.Sign.SLHDSA) == string(aid.Sign.SLHDSA) {
			t.Fatal("the account identity's secret key was copied to the linked device")
		}
		lines, err := l.deviceLines()
		if err != nil || len(lines) != 3 || !strings.Contains(strings.Join(lines, "\n"), "this one") {
			t.Fatalf("devices: %q, %v", lines, err)
		}
		// The fingerprint and the safety number are the account's, on every device.
		if got := l.safetyNumber(bob.app().v.AccountIdentity()); got != sn {
			t.Fatalf("safety number on the linked device is %s, on the first %s", got, sn)
		}
	})

	t.Run("a linked device cannot do what only the account identity may", func(t *testing.T) {
		l := laptop.app()
		if _, err := l.approve(make([]byte, pqc.LinkSecretSize)); err == nil {
			t.Error("a linked device approved a device")
		}
		if _, err := l.unlink("00"); err == nil {
			t.Error("a linked device unlinked a device")
		}
		laptop.use()
		if err := cmdRecoveryCode(); err == nil {
			t.Error("a linked device showed a recovery code")
		}
		// Not even with the relay's help: only the account identity signs lists.
		_, lid := l.v.Me()
		forged, _ := pqc.SignDeviceList(lid, "alice", 9, nil)
		if err := l.rc.SetDevices(l.auth(), forged); err == nil {
			t.Error("the relay took a device list signed by a linked device")
		}
	})

	t.Run("a contact's next message reaches the new device too, and says so once", func(t *testing.T) {
		bob.mustSend("alice", "to all of you") // bob only knew the first device: the relay makes him look again
		expectTexts(t, alice.pull("bob"), "to all of you")
		expectTexts(t, laptop.pull("bob"), "to all of you")
		bob.mustSend("alice", "and again")
		expectTexts(t, alice.pull("bob"), "and again")
		expectTexts(t, laptop.pull("bob"), "and again")
		all := strings.Join(render(bob.app().v.GetMessages("alice")), "\n")
		if strings.Count(all, "linked a new device") != 1 || strings.Contains(all, "IDENTITY CHANGED") {
			t.Fatalf("bob should be told once about the device and not about an identity change:\n%s", all)
		}
		if got := bob.app().safetyNumber(alice.app().v.AccountIdentity()); got != sn {
			t.Fatal("a new device changed the safety number")
		}
		if info, _ := bob.app().v.ContactInfo("alice"); info.Devices != 2 {
			t.Fatalf("bob writes to %d devices of alice, want 2", info.Devices)
		}
	})

	t.Run("a device that only reads is not sent the handshake over and over", func(t *testing.T) {
		bob.mustSend("alice", "third")
		bob.mustSend("alice", "fourth")
		msgs, err := w.mem.Messages("mem-alice", laptop.app().v.DeviceID(), "bob", 10)
		if err != nil || len(msgs) != 2 {
			t.Fatalf("%d waiting for the laptop, %v", len(msgs), err)
		}
		for _, m := range msgs {
			var wm pqc.WireMsg
			_ = json.Unmarshal(m.Payload, &wm)
			if wm.Type != pqc.WireEnvelope || len(m.Payload) > 20<<10 {
				t.Fatalf("a %d byte message of type %d for a device that has the handshake already", len(m.Payload), wm.Type)
			}
		}
		expectTexts(t, laptop.pull("bob"), "third", "fourth")
		expectTexts(t, alice.pull("bob"), "third", "fourth")
	})

	t.Run("what one device sends shows up on the other", func(t *testing.T) {
		laptop.mustSend("bob", "sent from the laptop")
		expectTexts(t, bob.pull("alice"), "sent from the laptop")
		alice.pull("bob")
		if got := alice.sent("bob"); got[len(got)-1] != "sent from the laptop" {
			t.Fatalf("the first device does not show what the laptop sent: %q", got)
		}
		alice.mustSend("bob", "sent from the first device")
		expectTexts(t, bob.pull("alice"), "sent from the first device")
		laptop.pull("bob")
		if got := laptop.sent("bob"); len(got) != 2 || got[1] != "sent from the first device" {
			t.Fatalf("the laptop does not show what the first device sent: %q", got)
		}
		// A reply reaches both, in both conversations in the same order.
		bob.mustSend("alice", "got both")
		expectTexts(t, alice.pull("bob"), "got both")
		expectTexts(t, laptop.pull("bob"), "got both")
		if n := len(alice.app().v.ContactList()); n != 1 {
			t.Fatalf("one's own devices must not show up as a conversation: %d contacts", n)
		}
	})

	t.Run("nobody but one's own devices can report sent messages", func(t *testing.T) {
		b := bob.app()
		err := b.v.Update(func() error {
			return queue(b, "alice", randID(), pqc.PackSync("carol", "words put in alice's mouth", time.Now().Unix()))
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.flush(); err != nil {
			t.Fatal(err)
		}
		alice.pull("bob")
		if got := alice.sent("carol"); len(got) != 0 {
			t.Fatalf("a contact made alice's device show a message she never sent: %q", got)
		}
	})

	t.Run("a stranger is first written to by a linked device", func(t *testing.T) {
		carol := w.ready(t, "carol")
		laptop.mustSend("carol", "hi, alice here (from the laptop)")
		got := carol.pull("alice")
		expectTexts(t, got, "hi, alice here (from the laptop)")
		if !strings.Contains(notices(got), "New conversation") {
			t.Fatalf("no first-contact notice: %q", got)
		}
		info, known := carol.app().v.ContactInfo("alice")
		if !known || !pqc.IdentityEqual(info.Identity, alice.app().v.AccountIdentity()) {
			t.Fatal("carol must remember the ACCOUNT identity, not the laptop's key")
		}
		carol.mustSend("alice", "hello alice")
		expectTexts(t, alice.pull("carol"), "hello alice")
		expectTexts(t, laptop.pull("carol"), "hello alice")
	})

	t.Run("unlinking: the device is out, for the relay and for contacts", func(t *testing.T) {
		l := laptop.app()
		var late []byte // what the unlinked device (or a thief holding it) would send afterwards
		err := l.v.Update(func() error {
			wire, _, err := l.v.Seal("bob", l.v.Reach("bob")[0], pqc.PackInner("still me, honest"))
			late = rawWire(l, wire)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		msg, err := alice.app().unlink(l.v.DeviceID()[:6])
		if err != nil || !strings.Contains(msg, "unlinked") {
			t.Fatalf("unlink: %q, %v", msg, err)
		}
		// The relay does not know it any more...
		if _, err := laptop.app().pull(0); err == nil || !strings.Contains(explain(err), "unlinked") {
			t.Fatalf("an unlinked device still gets served: %v", err)
		}
		// ...the next message goes to the first device only...
		bob.mustSend("alice", "just you now")
		expectTexts(t, alice.pull("bob"), "just you now")
		if info, _ := bob.app().v.ContactInfo("alice"); info.Devices != 1 {
			t.Fatalf("bob still writes to %d devices", info.Devices)
		}
		// ...and bob, who has seen the new list, takes nothing from the removed device,
		// even if a relay delivered it.
		first, _, _ := w.mem.DeviceIDs("mem-bob")
		if stored, _ := w.mem.PutMessages("mem-bob", "alice", map[string][]byte{first: late}, 100); !stored {
			t.Fatal("could not inject")
		}
		if got := bob.pull("alice"); len(texts(got)) != 0 {
			t.Fatalf("a message from an unlinked device was shown: %q", got)
		}
		// The first device still works in both directions.
		alice.mustSend("bob", "all good here")
		expectTexts(t, bob.pull("alice"), "all good here")
	})

	t.Run("an old device list cannot bring a removed device back", func(t *testing.T) {
		b := bob.app()
		_, aid := alice.app().v.Me()
		_, lid := laptop.app().v.Me()
		old, err := pqc.SignDeviceList(aid, "alice", 1, [][]byte{lid.Pub.Encode()}) // version 1 named the laptop
		if err != nil {
			t.Fatal(err)
		}
		_ = b.v.Update(func() error {
			if _, taken := b.v.SetDevices("alice", old.V, old.Keys, nil); taken {
				t.Error("bob's device took an older list")
			}
			return nil
		})
		if bob.app().v.ValidDevice("alice", lid.Pub.Encode()) {
			t.Fatal("the removed device is valid again")
		}
	})
}

func TestLinkedDeviceLeaves(t *testing.T) {
	w := newWorld(t)
	alice, bob := w.ready(t, "alice"), w.ready(t, "bob")
	phone := alice.second(t)
	w.link(t, alice, phone)
	bob.mustSend("alice", "hello")
	expectTexts(t, phone.pull("bob"), "hello")
	expectTexts(t, alice.pull("bob"), "hello")

	// `itter burn` on the linked device wipes it and tells the relay; the account stays.
	out, err := phone.burn()
	if err != nil || !strings.Contains(out, "unlink") {
		t.Fatalf("burn on a linked device: %q, %v", out, err)
	}
	bob.mustSend("alice", "after the phone is gone")
	expectTexts(t, alice.pull("bob"), "after the phone is gone")
	alice.mustSend("bob", "still here")
	expectTexts(t, bob.pull("alice"), "still here")
	if _, err := w.ts.Client().Get(w.ts.URL + "/v1/keys/alice"); err != nil {
		t.Fatal(err)
	}

	// Burning the FIRST device releases the identity: linked devices stop working too.
	tablet := alice.second(t)
	w.link(t, alice, tablet)
	if _, err := alice.burn(); err != nil {
		t.Fatal(err)
	}
	if _, err := tablet.app().pull(0); err == nil {
		t.Fatal("a linked device outlived its account identity")
	}
	if _, err := bob.app().send("alice", "anyone?"); err == nil {
		// queued sessions exist, so the send itself may go through to a failure notice
		msgs := bob.app().v.GetMessages("alice")
		if !strings.Contains(msgs[len(msgs)-1].Text, "NOT delivered") && !strings.Contains(msgs[len(msgs)-1].Text, "no DM identity") {
			t.Fatalf("a message to a released account looked delivered: %q", msgs[len(msgs)-1].Text)
		}
	}
}

func TestIgnore(t *testing.T) {
	w := newWorld(t)
	alice, bob, mallory := w.ready(t, "alice"), w.ready(t, "bob"), w.ready(t, "mallory")
	mallory.mustSend("alice", "hey")
	expectTexts(t, alice.pull("mallory"), "hey")
	mallory.mustSend("alice", "hey!!")
	bob.mustSend("alice", "hi alice")

	msg, err := alice.app().setIgnore("@Mallory", true)
	if err != nil || !strings.Contains(msg, "Ignoring @mallory") {
		t.Fatalf("ignore: %q, %v", msg, err)
	}
	if got := alice.pull("mallory"); len(got) != 0 {
		t.Fatalf("what an ignored sender had waiting was delivered: %q", got)
	}
	expectTexts(t, texts(render(alice.app().v.GetMessages("bob"))), "hi alice") // everyone else is unaffected

	// The ignored sender sees nothing unusual; nothing arrives.
	mallory.mustSend("alice", "hello??") // "sent", as far as mallory can tell
	if got := alice.pull("mallory"); len(got) != 0 {
		t.Fatalf("an ignored sender got through: %q", got)
	}
	if n := w.mem.Pending("alice"); n != 0 {
		t.Fatalf("%d message(s) from an ignored sender are stored", n)
	}
	alice.use()
	out, _ := capture(func() error { return cmdIgnore(nil, true) })
	if !strings.Contains(out, "@mallory") {
		t.Fatalf("ignore list: %q", out)
	}
	if _, err := alice.app().setIgnore("alice", true); err == nil {
		t.Fatal("ignoring oneself")
	}
	if _, err := alice.app().setIgnore("nosuchuser", true); err == nil || !strings.Contains(err.Error(), "no itter user") {
		t.Fatalf("ignoring nobody: %v", err)
	}

	// Undone, the conversation simply goes on (what was dropped stays dropped).
	if _, err := alice.app().setIgnore("mallory", false); err != nil {
		t.Fatal(err)
	}
	mallory.mustSend("alice", "sorry about before")
	got := alice.pull("mallory")
	expectTexts(t, got, "sorry about before")
	if n := notices(got); n != "" {
		t.Fatalf("the gap left by the dropped messages broke the session: %s", n)
	}
	if list := alice.app().v.IgnoreList(); len(list) != 0 {
		t.Fatalf("still ignored locally: %v", list)
	}
}

// Someone who was ignored BEFORE their first message: the relay took their
// handshake and dropped it. Their device must not rely on it having arrived.
func TestIgnoredBeforeTheFirstMessage(t *testing.T) {
	w := newWorld(t)
	alice, dave := w.ready(t, "alice"), w.ready(t, "dave")
	if _, err := alice.app().setIgnore("dave", true); err != nil {
		t.Fatal(err)
	}
	dave.mustSend("alice", "first")
	dave.mustSend("alice", "second")
	if _, err := alice.app().setIgnore("dave", false); err != nil {
		t.Fatal(err)
	}

	// Right after, dave's device still thinks alice has the handshake.
	dave.mustSend("alice", "third")
	got := alice.pull("dave")
	if len(texts(got)) != 0 || !strings.Contains(notices(got), "the key exchange they belong to never reached this device") {
		t.Fatalf("a message without its handshake: %q", got)
	}

	// No answer for a while: the handshake goes along again by itself.
	first := pqc.ReattachFirst
	pqc.ReattachFirst = 0
	defer func() { pqc.ReattachFirst = first }()
	dave.mustSend("alice", "fourth")
	pqc.ReattachFirst = first
	got = alice.pull("dave")
	expectTexts(t, got, "fourth")
	if !strings.Contains(notices(got), "New conversation") {
		t.Fatalf("no first-contact notice: %q", got)
	}
	dave.mustSend("alice", "fifth") // and not on every message from then on
	msgs, _ := w.mem.Messages("mem-alice", alice.app().v.DeviceID(), "dave", 10)
	if len(msgs) != 1 || len(msgs[0].Payload) > 20<<10 {
		t.Fatalf("%d waiting, the first of %d bytes", len(msgs), len(msgs[0].Payload))
	}
	expectTexts(t, alice.pull("dave"), "fifth")
	alice.mustSend("dave", "sorry, you were on my ignore list")
	expectTexts(t, dave.pull("alice"), "sorry, you were on my ignore list")
}

// The other way out of the same situation: the one who has no session writes.
func TestWritingSetsUpTheMissingSession(t *testing.T) {
	w := newWorld(t)
	alice, dave := w.ready(t, "alice"), w.ready(t, "dave")
	if _, err := alice.app().setIgnore("dave", true); err != nil {
		t.Fatal(err)
	}
	dave.mustSend("alice", "first")
	if _, err := alice.app().setIgnore("dave", false); err != nil {
		t.Fatal(err)
	}
	dave.mustSend("alice", "second")
	if got := alice.pull("dave"); len(texts(got)) != 0 {
		t.Fatalf("readable without a handshake: %q", got)
	}
	alice.mustSend("dave", "what did you write?")
	expectTexts(t, dave.pull("alice"), "what did you write?")
	dave.mustSend("alice", "second, again")
	expectTexts(t, alice.pull("dave"), "second, again")
}

func TestShellDevicesAndIgnore(t *testing.T) {
	w := newWorld(t)
	alice, bob := w.ready(t, "alice"), w.ready(t, "bob")
	bob.mustSend("alice", "hi")
	s := newShell(t, alice)
	alice.pull("bob")
	s.feed(pollMsg{})

	s.line("/devices")
	s.wantView("first device (holds the account identity) · this one")
	s.wantView("To add one: run `itter link alice` on the new device.")
	s.line("/approve not-a-code")
	s.wantView("Usage: /approve <code>")
	s.line("/unlink")
	s.wantView("Usage: /unlink <device id>")

	// A new device is let in from inside the shell.
	laptop := alice.second(t)
	w.linkWith(t, alice, laptop, func(code []byte) error {
		// Asked for like this, the shell explains what it means and wants a word more.
		s.line("/approve " + api.FormatRecovery(code))
		if !strings.Contains(s.view(), "This lets another device read and send @alice's DMs") || strings.Contains(s.view(), "Linked device") {
			t.Fatalf("approve without confirmation:\n%s", s.view())
		}
		s.line("/approve " + api.FormatRecovery(code) + " LINK")
		if !strings.Contains(s.view(), "Linked device") {
			return errors.New(s.view())
		}
		return nil
	})
	s.line("/clear")
	s.line("/devices")
	s.wantView("linked device")
	s.wantNoView("To add one")

	s.line("/ignore @bob")
	s.wantView("Ignoring @bob: their DMs no longer reach you, and they are not told.")
	s.line("/clear")
	s.line("/ignore")
	s.wantView("You ignore: @bob")
	bob.mustSend("alice", "hello?")
	if got := alice.pull("bob"); len(texts(got)) != 0 {
		t.Fatalf("an ignored sender got through: %q", got)
	}
	s.line("/unignore @bob")
	s.wantView("No longer ignoring @bob.")
	s.line("/clear")
	s.line("/ignore")
	s.wantView("You ignore nobody.")

	s.line("/unlink " + laptop.app().v.DeviceID()[:6])
	s.wantView("is unlinked: it no longer receives your messages")
	s.line("/clear")
	s.line("/devices")
	s.wantView("To add one")
}

// junk fills the relay's queue for one device of an account with n messages
// in from's name, the way a long absence would.
func (w *world) junk(t *testing.T, to, dev string, from *user, n int) {
	t.Helper()
	fromDev := from.app().v.DeviceID()
	for i := 0; i < n; i++ {
		raw, _ := json.Marshal(pqc.WireMsg{Type: pqc.WireEnvelope, From: from.name, Dev: fromDev,
			Payload: json.RawMessage(fmt.Sprintf(`{"v":2,"env":"AAA%d"}`, i))})
		if ok, err := w.mem.PutMessages("mem-"+to, from.name, map[string][]byte{dev: raw}, n); !ok || err != nil {
			t.Fatalf("filling the queue: %v, %v", ok, err)
		}
	}
}

func TestADeviceThatIsAwayDoesNotHoldUpTheOthers(t *testing.T) {
	const full = 500 // the relay keeps this many messages per sender and device
	w := newWorld(t)
	alice, bob, carol := w.ready(t, "alice"), w.ready(t, "bob"), w.ready(t, "carol")
	laptop := alice.second(t)
	w.link(t, alice, laptop)
	bob.mustSend("alice", "one")
	expectTexts(t, alice.pull("bob"), "one")
	expectTexts(t, laptop.pull("bob"), "one")
	lid := laptop.app().v.DeviceID()

	t.Run("the others still get their messages", func(t *testing.T) {
		w.junk(t, "alice", lid, bob, full-1)
		bob.mustSend("alice", "two") // the last one the laptop's queue has room for
		bob.mustSend("alice", "three")
		expectTexts(t, alice.pull("bob"), "two", "three")
		if waiting, _ := w.mem.Senders("mem-alice", lid); waiting["bob"] != full {
			t.Fatalf("%d messages wait for the device that is away, the limit is %d", waiting["bob"], full)
		}
		// Back again, it reads what was kept and is in step from then on.
		got := laptop.pull("bob")
		expectTexts(t, got, "two")
		if !strings.Contains(notices(got), "could not be decrypted") {
			t.Fatalf("the junk in the queue went unnoticed: %q", notices(got))
		}
		bob.mustSend("alice", "four")
		expectTexts(t, laptop.pull("bob"), "four") // "three" is missing here, and only here
		expectTexts(t, alice.pull("bob"), "four")
	})

	t.Run("when nobody has room the sender keeps the message, and says so", func(t *testing.T) {
		_, ids, _ := w.mem.DeviceIDs("mem-carol")
		alice.mustSend("carol", "hello carol")
		expectTexts(t, carol.pull("alice"), "hello carol")
		w.junk(t, "carol", ids[0], alice, full)
		out := alice.send("carol", "are you there?")
		if out.Status != vault.StatusQueued || !strings.Contains(out.Note, "too many unread messages") {
			t.Fatalf("sent into a full inbox: %+v", out)
		}
		// One's other devices are told about a message only once the relay has it.
		laptop.pull("carol")
		if got := laptop.sent("carol"); len(got) != 1 || got[0] != "hello carol" {
			t.Fatalf("the laptop shows as sent: %q", got)
		}
		carol.pull("alice") // reads (and thereby makes room)
		if err := alice.app().flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		expectTexts(t, carol.pull("alice"), "are you there?")
		laptop.pull("carol")
		if got := laptop.sent("carol"); len(got) != 2 || got[1] != "are you there?" {
			t.Fatalf("after delivery the laptop shows as sent: %q", got)
		}
	})
}

// typed runs fn with text on standard input, as if the user had typed it.
func typed(text string, fn func() error) (string, error) {
	r, w, _ := os.Pipe()
	fmt.Fprintln(w, text)
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	return capture(fn)
}

// Approving a device hands over the account. The command says so and wants
// a word of confirmation before it does anything.
func TestApproveAsksFirst(t *testing.T) {
	w := newWorld(t)
	alice := w.ready(t, "alice")
	code := api.FormatRecovery(make([]byte, pqc.LinkSecretSize))
	alice.use()
	out, err := typed("yes", func() error { return cmdApprove([]string{code}) })
	if err == nil || !strings.Contains(out, "read and send @alice's DMs") || !strings.Contains(err.Error(), "nothing was linked") {
		t.Fatalf("approve without the confirmation word: %q, %v", out, err)
	}
	// Confirmed, it goes on (here: to find that no device is waiting).
	for _, run := range []func() error{
		func() error { _, err := typed("LINK", func() error { return cmdApprove([]string{code}) }); return err },
		func() error {
			_, err := capture(func() error { return cmdApprove([]string{code, "--yes"}) })
			return err
		},
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "no device is waiting") {
			t.Fatalf("confirmed approve: %v", err)
		}
	}
	if _, err := capture(func() error { return cmdApprove([]string{"not a code"}) }); err == nil || !strings.Contains(err.Error(), "not a valid link code") {
		t.Fatalf("approve with nonsense: %v", err)
	}
}
