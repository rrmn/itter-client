package pqc

import (
	"bytes"
	"testing"
	"time"
)

func TestDeviceList(t *testing.T) {
	account, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := GenerateIdentity()
	d1, _ := GenerateIdentity()
	d2, _ := GenerateIdentity()
	acct, k1, k2 := account.Pub.Encode(), d1.Pub.Encode(), d2.Pub.Encode()

	l, err := SignDeviceList(account, "Alice", 1, [][]byte{k1, k2})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Verify(acct, "alice"); err != nil { // names compare without case, like itter
		t.Fatalf("valid list rejected: %v", err)
	}
	if !l.Has(k1) || !l.Has(k2) || l.Has(acct) || l.Has(other.Pub.Encode()) || (*DeviceList)(nil).Has(k1) {
		t.Fatal("Has is wrong")
	}
	if l.Version() != 1 || (*DeviceList)(nil).Version() != 0 {
		t.Fatal("Version is wrong")
	}
	if l.Verify(acct, "bob") == nil {
		t.Fatal("a list for one account was accepted for another")
	}
	if l.Verify(other.Pub.Encode(), "alice") == nil {
		t.Fatal("a list was accepted under a different account identity")
	}
	for name, change := range map[string]func(*DeviceList){
		"version raised":  func(c *DeviceList) { c.V = 2 },
		"device added":    func(c *DeviceList) { c.Keys = append(c.Keys, other.Pub.Encode()) },
		"device removed":  func(c *DeviceList) { c.Keys = c.Keys[:1] },
		"device swapped":  func(c *DeviceList) { c.Keys = [][]byte{k1, other.Pub.Encode()} },
		"order changed":   func(c *DeviceList) { c.Keys = [][]byte{k2, k1} },
		"signature bytes": func(c *DeviceList) { c.Sig = append([]byte{}, c.Sig...); c.Sig[len(c.Sig)/2] ^= 1 },
		"no signature":    func(c *DeviceList) { c.Sig = nil },
	} {
		c := &DeviceList{V: l.V, Keys: append([][]byte{}, l.Keys...), Sig: l.Sig}
		change(c)
		if c.Verify(acct, "alice") == nil {
			t.Errorf("%s: a changed list still verifies", name)
		}
	}
	// Lists that must not even be signed.
	if _, err := SignDeviceList(account, "alice", 0, nil); err == nil {
		t.Error("version 0 is reserved for 'no list'")
	}
	if _, err := SignDeviceList(account, "alice", 1, [][]byte{k1, k1}); err == nil {
		t.Error("duplicate device")
	}
	if _, err := SignDeviceList(account, "alice", 1, [][]byte{acct}); err == nil {
		t.Error("the account identity is not a linked device")
	}
	if _, err := SignDeviceList(account, "alice", 1, [][]byte{[]byte("junk")}); err == nil {
		t.Error("junk key")
	}
	many := [][]byte{k1, k2, other.Pub.Encode(), bytes.Repeat([]byte{1}, len(k1)), bytes.Repeat([]byte{2}, len(k1))}
	if _, err := SignDeviceList(account, "alice", 1, many); err == nil {
		t.Error("too many devices")
	}
	// An empty list is how the last linked device is removed.
	empty, err := SignDeviceList(account, "alice", 7, nil)
	if err != nil || empty.Verify(acct, "alice") != nil || empty.Has(k1) {
		t.Fatalf("empty list: %v", err)
	}
}

func TestLinkTags(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, LinkSecretSize)
	wrong := bytes.Repeat([]byte{8}, LinkSecretSize)
	dev, acct := []byte("device key"), []byte("account identity")

	if LinkID(secret) == LinkID(wrong) || len(LinkID(secret)) != 32 {
		t.Fatal("link ids")
	}
	req := LinkRequestTag(secret, "Alice", dev)
	if !TagEqual(req, LinkRequestTag(secret, "alice", dev)) {
		t.Fatal("same request, different tag")
	}
	for name, other := range map[string][]byte{
		"other code":    LinkRequestTag(wrong, "alice", dev),
		"other account": LinkRequestTag(secret, "bob", dev),
		"other device":  LinkRequestTag(secret, "alice", []byte("attacker key")),
		"a result tag":  LinkResultTag(secret, "alice", acct, dev, 1),
		"empty":         nil,
	} {
		if TagEqual(req, other) {
			t.Errorf("request tag equals the tag for: %s", name)
		}
	}
	res := LinkResultTag(secret, "alice", acct, dev, 3)
	for name, other := range map[string][]byte{
		"other identity": LinkResultTag(secret, "alice", []byte("fake identity"), dev, 3),
		"other version":  LinkResultTag(secret, "alice", acct, dev, 2),
		"other device":   LinkResultTag(secret, "alice", acct, []byte("x"), 3),
		"other code":     LinkResultTag(wrong, "alice", acct, dev, 3),
	} {
		if TagEqual(res, other) {
			t.Errorf("result tag equals the tag for: %s", name)
		}
	}
}

func TestHandshakeStopsRidingAlongOnceDelivered(t *testing.T) {
	a, b := start(t, true)
	w1 := send(t, a, "one")
	if w1.Type != WireInitial || !a.sess.AwaitsReply() {
		t.Fatal("the first message must carry the handshake")
	}
	w2 := send(t, a, "two") // nothing delivered yet: still attached
	if w2.Type != WireInitial {
		t.Fatal("the handshake must ride along until it is known to be delivered")
	}
	a.sess.HandshakeDelivered() // the relay took a message that carried it
	a.sess.HandshakeDelivered() // (several that did, at the same time: counts once)
	w3 := send(t, a, "three")
	if w3.Type != WireEnvelope || !a.sess.AwaitsReply() || a.sess.InitSends != 1 {
		t.Fatal("after the relay took the handshake, the next message goes without it")
	}
	// The relay taking it proves nothing about the peer: without an answer
	// the handshake goes along again, after 10 minutes, then 20, 40, ...
	later := func(d time.Duration) { a.sess.InitSentAt -= int64(d / time.Second) }
	later(ReattachFirst - time.Minute)
	if w := send(t, a, "too early"); w.Type != WireEnvelope {
		t.Fatal("the handshake was attached again before it was due")
	}
	later(time.Minute)
	w4 := send(t, a, "four")
	if w4.Type != WireInitial {
		t.Fatal("no answer for a while: the handshake must be attached again")
	}
	a.sess.HandshakeDelivered()
	if w := send(t, a, "five"); w.Type != WireEnvelope || a.sess.InitSends != 2 {
		t.Fatal("...once, not from then on")
	}
	later(2*ReattachFirst - time.Minute)
	if w := send(t, a, "six"); w.Type != WireEnvelope {
		t.Fatal("the second wait must be twice as long as the first")
	}
	// ...and never longer than a day, however long there has been no answer.
	a.sess.InitSends = 1000
	later(ReattachMax)
	if w := send(t, a, "seven"); w.Type != WireInitial {
		t.Fatal("the handshake must go along at least once a day")
	}
	a.sess.InitSentAt = time.Now().Unix() + 3600 // a clock that was set back
	if w := send(t, a, "eight"); w.Type != WireInitial {
		t.Fatal("a timestamp from the future must not silence the handshake")
	}
	a.sess.HandshakeDelivered()
	// The receiver gets them in order and needs the handshake only once.
	expect(t, b, w1, "one")
	expect(t, b, w2, "two")
	expect(t, b, w3, "three")
	expect(t, b, w4, "four")
	// Once the peer has answered, the handshake is never sent again.
	expect(t, a, send(t, b, "reply"), "reply")
	a.sess.InitSends, a.sess.InitSentAt = 0, 0
	if w := send(t, a, "nine"); w.Type != WireEnvelope || a.sess.AwaitsReply() {
		t.Fatal("the handshake was attached after the peer had answered")
	}
}
