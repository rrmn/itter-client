package pqc

import (
	"bytes"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"testing"
)

// Fixtures are generated once: SLH-DSA signing makes identities and signed
// prekeys deliberately slow.
type party struct {
	name string
	id   *Identity
	spk  *PreKey
	spkP *PreKeyPublic
	otpk map[uint32]*PreKey
	otpP []*PreKeyPublic
}

var (
	fixOnce    sync.Once
	alice, bob *party
	mallory    *party
)

func newParty(t testing.TB, name string, otpks int) *party {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	spk, spkP, err := GenerateSignedPreKey(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	p := &party{name: name, id: id, spk: spk, spkP: spkP, otpk: map[uint32]*PreKey{}}
	for i := uint32(0); i < uint32(otpks); i++ {
		k, kp, err := GenerateOneTimePreKey(100 + i)
		if err != nil {
			t.Fatal(err)
		}
		p.otpk[k.ID] = k
		p.otpP = append(p.otpP, kp)
	}
	return p
}

func fixtures(t testing.TB) {
	fixOnce.Do(func() {
		alice = newParty(t, "alice", 0)
		bob = newParty(t, "bob", 8)
		mallory = newParty(t, "mallory", 0)
	})
}

func (p *party) bundle(withOTPK bool) *PublicBundle {
	b := &PublicBundle{Username: p.name, Identity: p.id.Pub.Encode(), SPK: p.spkP, SPKSig: p.spk.Sig}
	if withOTPK && len(p.otpP) > 0 {
		b.OTPK = p.otpP[0]
		p.otpP = p.otpP[1:]
	}
	return b
}

// endpoint mimics the client's receive logic for one peer.
type endpoint struct {
	me   *party
	sess *Session
}

func (e *endpoint) receive(t testing.TB, w *WireMsg) ([]byte, error) {
	switch w.Type {
	case WireInitial:
		ip, err := ParseInitial(w)
		if err != nil {
			return nil, err
		}
		if e.sess != nil && bytes.Equal(e.sess.HandshakeID, ip.HS.HandshakeID()) {
			return e.sess.Decrypt(ip.Env)
		}
		s, err := Respond(e.me.id, e.me.name, e.me.spk, e.me.otpk[ip.HS.OTPKID], ip.HS)
		if err != nil {
			return nil, err
		}
		pt, err := s.Decrypt(ip.Env)
		if err != nil {
			return nil, err
		}
		delete(e.me.otpk, ip.HS.OTPKID)
		e.sess = s
		return pt, nil
	case WireEnvelope:
		ep, err := ParseEnvelope(w)
		if err != nil {
			return nil, err
		}
		if e.sess == nil {
			return nil, fmt.Errorf("no session")
		}
		return e.sess.Decrypt(ep.Env)
	}
	return nil, fmt.Errorf("bad type")
}

func mustJSON(t testing.TB, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func start(t testing.TB, withOTPK bool) (*endpoint, *endpoint) {
	fixtures(t)
	s, err := Initiate(alice.id, "alice", bob.bundle(withOTPK))
	if err != nil {
		t.Fatal(err)
	}
	return &endpoint{me: alice, sess: s}, &endpoint{me: bob}
}

func send(t testing.TB, from *endpoint, text string) *WireMsg {
	w, err := from.sess.Seal(from.me.name, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func expect(t testing.TB, to *endpoint, w *WireMsg, text string) {
	t.Helper()
	pt, err := to.receive(t, w)
	if err != nil {
		t.Fatalf("%s failed to decrypt %q: %v", to.me.name, text, err)
	}
	if string(pt) != text {
		t.Fatalf("got %q want %q", pt, text)
	}
}

func TestHandshakeAndPingPongAdvancesBothPQRatchets(t *testing.T) {
	a, b := start(t, true)
	for i := 0; i < 40; i++ {
		m := fmt.Sprintf("a%d", i)
		expect(t, b, send(t, a, m), m)
		m = fmt.Sprintf("b%d", i)
		expect(t, a, send(t, b, m), m)
	}
	ml, fr := a.sess.PQEpochs()
	ml2, fr2 := b.sess.PQEpochs()
	t.Logf("after 80 messages: ML-KEM epochs %d/%d, FrodoKEM epochs %d/%d", ml, ml2, fr, fr2)
	if ml < 4 || fr < 2 {
		t.Fatalf("PQ ratchets did not advance enough: mlkem=%d frodo=%d", ml, fr)
	}
	if a.sess.PendingInit != nil {
		t.Fatal("handshake must stop being re-sent after the first reply")
	}
}

func TestNoOneTimePrekey(t *testing.T) {
	a, b := start(t, false)
	expect(t, b, send(t, a, "hi"), "hi")
	expect(t, a, send(t, b, "yo"), "yo")
}

func TestLostFirstMessageAndRepeatedHandshake(t *testing.T) {
	a, b := start(t, true)
	_ = send(t, a, "lost")
	w2 := send(t, a, "second")
	w3 := send(t, a, "third")
	if w2.Type != WireInitial || w3.Type != WireInitial {
		t.Fatal("handshake must be repeated until the peer replies")
	}
	expect(t, b, w3, "third") // out of order too
	expect(t, b, w2, "second")
	r := send(t, b, "reply")
	expect(t, a, r, "reply")
	w4 := send(t, a, "after")
	if w4.Type != WireEnvelope {
		t.Fatal("expected a plain envelope after the reply")
	}
	expect(t, b, w4, "after")
}

func TestForgedAndReplayedMessagesLeaveStateUntouched(t *testing.T) {
	a, b := start(t, true)
	expect(t, b, send(t, a, "hello"), "hello")
	expect(t, a, send(t, b, "hey"), "hey")

	w := send(t, a, "secret")
	ep, _ := ParseEnvelope(w)
	before := mustJSON(t, b.sess)
	r := mrand.New(mrand.NewPCG(7, 7))
	for i := 0; i < 200; i++ {
		bad := append([]byte(nil), ep.Env...)
		bad[r.IntN(len(bad))] ^= byte(1 + r.IntN(255))
		if _, err := b.sess.Decrypt(bad); err == nil {
			t.Fatal("forged message accepted")
		}
	}
	if !bytes.Equal(before, mustJSON(t, b.sess)) {
		t.Fatal("rejected messages changed the session state")
	}
	expect(t, b, w, "secret")
	after := mustJSON(t, b.sess)
	if _, err := b.receive(t, w); err == nil {
		t.Fatal("replay accepted")
	}
	if !bytes.Equal(after, mustJSON(t, b.sess)) {
		t.Fatal("replay changed the session state")
	}
}

func TestMalloryCannotImpersonateAlice(t *testing.T) {
	fixtures(t)
	// Mallory runs the handshake honestly but claims Alice's identity.
	s, err := Initiate(mallory.id, "mallory", bob.bundle(false))
	if err != nil {
		t.Fatal(err)
	}
	w, _ := s.Seal("alice", []byte("trust me"))
	ip, _ := ParseInitial(w)
	ip.HS.Identity = alice.id.Pub.Encode()
	if _, err := Respond(bob.id, "bob", bob.spk, nil, ip.HS); err == nil {
		t.Fatal("handshake with a stolen identity must fail signature verification")
	}
	// A swapped ephemeral key breaks the signed transcript as well.
	s2, _ := Initiate(alice.id, "alice", bob.bundle(false))
	w2, _ := s2.Seal("alice", []byte("x"))
	ip2, _ := ParseInitial(w2)
	ip2.HS.EK[0] ^= 1
	if _, err := Respond(bob.id, "bob", bob.spk, nil, ip2.HS); err == nil {
		t.Fatal("tampered handshake accepted")
	}
}

// The account names are part of what the initiator signs: a relay cannot
// pass one user's handshake off as another's, or deliver it to someone else.
func TestHandshakeIsBoundToAccountNames(t *testing.T) {
	fixtures(t)
	fresh := func() *InitHandshake {
		s, err := Initiate(mallory.id, "mallory", bob.bundle(false))
		if err != nil {
			t.Fatal(err)
		}
		w, _ := s.Seal("mallory", []byte("hi"))
		ip, _ := ParseInitial(w)
		return ip.HS
	}
	hs := fresh()
	if sess, err := Respond(bob.id, "bob", bob.spk, nil, hs); err != nil || sess.TheirUsername != "mallory" {
		t.Fatalf("honest handshake: %v", err)
	}
	if _, err := Respond(bob.id, "BOB", bob.spk, nil, hs); err != nil {
		t.Fatalf("names must compare without regard to case: %v", err)
	}
	relabelled := fresh()
	relabelled.From = "alice" // the relay files mallory's handshake under alice
	if _, err := Respond(bob.id, "bob", bob.spk, nil, relabelled); err == nil {
		t.Fatal("a handshake with a changed sender name was accepted")
	}
	if _, err := Respond(bob.id, "carol", bob.spk, nil, fresh()); err == nil {
		t.Fatal("a handshake addressed to bob was accepted by carol")
	}
	redirected := fresh()
	redirected.To = "carol"
	if _, err := Respond(bob.id, "carol", bob.spk, nil, redirected); err == nil {
		t.Fatal("a re-addressed handshake was accepted")
	}
}

func TestForgedBundleIsRejected(t *testing.T) {
	fixtures(t)
	bad := bob.bundle(false)
	bad.SPK = mallory.spkP // relay swaps in its own prekey
	if _, err := Initiate(alice.id, "alice", bad); err == nil {
		t.Fatal("bundle with a prekey not signed by the identity was accepted")
	}
	bad2 := bob.bundle(false)
	bad2.SPKSig = append([]byte(nil), bad2.SPKSig...)
	bad2.SPKSig[len(bad2.SPKSig)-1] ^= 1 // break only the SLH-DSA part
	if _, err := Initiate(alice.id, "alice", bad2); err == nil {
		t.Fatal("bundle with a broken SLH-DSA signature was accepted")
	}
}

// TestLossyReorderingNetwork simulates a relay that drops 15% of messages and
// delivers the rest out of order, with save/load of the state in between.
func TestLossyReorderingNetwork(t *testing.T) {
	a, b := start(t, true)
	expect(t, b, send(t, a, "init"), "init")
	expect(t, a, send(t, b, "ack"), "ack")
	r := mrand.New(mrand.NewPCG(42, 1))
	type inflight struct {
		w    *WireMsg
		text string
		to   *endpoint
	}
	var queue []inflight
	delivered, dropped := 0, 0
	for step := 0; step < 600; step++ {
		from, to := a, b
		if r.IntN(2) == 0 {
			from, to = b, a
		}
		txt := fmt.Sprintf("%s-%d", from.me.name, step)
		w := send(t, from, txt)
		if r.IntN(100) < 15 {
			dropped++
		} else {
			queue = append(queue, inflight{w, txt, to})
		}
		// deliver a random queued message most of the time
		for len(queue) > 0 && r.IntN(3) != 0 {
			i := r.IntN(len(queue))
			m := queue[i]
			queue = append(queue[:i], queue[i+1:]...)
			expect(t, m.to, m.w, m.text)
			delivered++
		}
		if step%50 == 0 { // vault save + reload
			for _, e := range []*endpoint{a, b} {
				var s Session
				if err := json.Unmarshal(mustJSON(t, e.sess), &s); err != nil {
					t.Fatal(err)
				}
				e.sess = &s
			}
		}
	}
	for _, m := range queue {
		expect(t, m.to, m.w, m.text)
		delivered++
	}
	ml, fr := a.sess.PQEpochs()
	t.Logf("delivered %d, dropped %d; ML-KEM epochs %d, FrodoKEM epochs %d", delivered, dropped, ml, fr)
	if ml < 10 || fr < 3 {
		t.Fatalf("PQ ratchets stalled under loss: mlkem=%d frodo=%d", ml, fr)
	}
}

func TestMessageOverhead(t *testing.T) {
	a, b := start(t, true)
	expect(t, b, send(t, a, "x"), "x")
	expect(t, a, send(t, b, "y"), "y")
	var total int
	for i := 0; i < 20; i++ {
		w := send(t, a, "hello there")
		total += len(mustJSON(t, w))
		expect(t, b, w, "hello there")
		expect(t, a, send(t, b, "ok"), "ok")
	}
	t.Logf("average wire size of a short DM: %d bytes (JSON, base64)", total/20)
	init, _ := Initiate(alice.id, "alice", bob.bundle(true))
	w, _ := init.Seal("alice", []byte("first"))
	t.Logf("initial message (repeated until reply): %d bytes", len(mustJSON(t, w)))
}
