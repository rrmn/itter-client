package pqc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"testing"
)

// The fuzz targets check two things for every decoder that sees bytes from
// the network: it never panics, and a rejected input never changes state.

func FuzzDecrypt(f *testing.F) {
	a, b := start(f, true)
	expect(f, b, send(f, a, "hello"), "hello")
	expect(f, a, send(f, b, "hey"), "hey")
	for i := 0; i < 3; i++ {
		ep, _ := ParseEnvelope(send(f, a, fmt.Sprintf("seed %d", i)))
		f.Add(ep.Env)
	}
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 'T'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}) // header length that overflows a 32-bit int
	frozen := mustJSON(f, b.sess)
	f.Fuzz(func(t *testing.T, env []byte) {
		var s Session
		if err := json.Unmarshal(frozen, &s); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Decrypt(env); err != nil {
			if !errors.Is(err, ErrDecrypt) && !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrDuplicate) {
				t.Fatalf("unexpected error type: %v", err)
			}
			if !bytes.Equal(frozen, mustJSON(t, &s)) {
				t.Fatal("a rejected message changed the session")
			}
		}
	})
}

func FuzzDecodeHeader(f *testing.F) {
	a, b := start(f, true)
	expect(f, b, send(f, a, "x"), "x")
	hdr, _ := func() ([]byte, []byte) {
		ep, _ := ParseEnvelope(send(f, b, "y"))
		hl := int(ep.Env[0])<<24 | int(ep.Env[1])<<16 | int(ep.Env[2])<<8 | int(ep.Env[3])
		return ep.Env[4 : 4+hl], nil
	}()
	f.Add(hdr)
	f.Add([]byte("TR\x02"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := decodeHeader(b)
		if err == nil && !bytes.Equal(h.encode(), b) {
			t.Fatal("header encoding is not canonical")
		}
	})
}

func FuzzDecodeIdentityKey(f *testing.F) {
	fixtures(f)
	f.Add(alice.id.Pub.Encode())
	f.Add([]byte("ITK2"))
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := DecodeIdentityKey(b)
		if err == nil && !bytes.Equal(k.Encode(), b) {
			t.Fatal("identity encoding is not canonical")
		}
	})
}

func FuzzHandshake(f *testing.F) {
	fixtures(f)
	s, err := Initiate(alice.id, "alice", bob.bundle(false))
	if err != nil {
		f.Fatal(err)
	}
	w, _ := s.Seal("alice", []byte("hi"))
	f.Add([]byte(w.Payload))
	f.Add([]byte(`{"v":2,"hs":{"v":2},"env":"AA=="}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		ip, err := ParseInitial(&WireMsg{Type: WireInitial, From: "alice", Payload: payload})
		if err != nil {
			return
		}
		_ = ip.HS.HandshakeID()
		if sess, err := Respond(bob.id, "bob", bob.spk, nil, ip.HS); err == nil {
			_, _ = sess.Decrypt(ip.Env)
		}
	})
}

func FuzzErasureDecoder(f *testing.F) {
	f.Add(uint16(0), []byte("0123456789abcdef"), uint16(7), []byte("fedcba9876543210"), 40)
	f.Fuzz(func(t *testing.T, i1 uint16, c1 []byte, i2 uint16, c2 []byte, size int) {
		if size < 1 || size > 4096 {
			return
		}
		d := newRSDecoder(size, 16)
		_ = d.add(i1, c1)
		_ = d.add(i2, c2)
		for i := uint16(100); !d.complete(); i++ {
			_ = d.add(i, bytes.Repeat([]byte{byte(i)}, 16))
		}
		if _, err := d.message(); err != nil {
			t.Fatal(err)
		}
	})
}

// TestScheduleStress drives two sessions through randomized schedules that
// are harsher than a relay would produce: one-sided bursts, both sides
// sending at once, loss, reordering, duplicates, and state save/reload.
func TestScheduleStress(t *testing.T) {
	seeds := 12
	if testing.Short() {
		seeds = 3
	}
	for seed := uint64(1); seed <= uint64(seeds); seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			r := mrand.New(mrand.NewPCG(seed, 99))
			a, b := start(t, seed%2 == 0)
			expect(t, b, send(t, a, "init"), "init")
			expect(t, a, send(t, b, "ack"), "ack")
			type flight struct {
				w    *WireMsg
				text string
				to   *endpoint
				age  int
			}
			var air []flight
			delivered, dups := 0, 0
			deliver := func(i int) {
				m := air[i]
				air = append(air[:i], air[i+1:]...)
				expect(t, m.to, m.w, m.text)
				delivered++
				if r.IntN(10) == 0 { // the relay redelivers
					if _, err := m.to.receive(t, m.w); !errors.Is(err, ErrDuplicate) {
						t.Fatalf("duplicate delivery: got %v, want ErrDuplicate", err)
					}
					dups++
				}
			}
			for step := 0; step < 400; step++ {
				from, to := a, b
				if r.IntN(2) == 0 {
					from, to = b, a
				}
				burst := 1
				switch r.IntN(12) {
				case 0:
					burst = 2 + r.IntN(30) // one side talks a lot
				case 1:
					burst = 0
				}
				for i := 0; i < burst; i++ {
					txt := fmt.Sprintf("%s-%d-%d", from.me.name, step, i)
					w := send(t, from, txt)
					if r.IntN(100) < 10 {
						continue // lost for good
					}
					air = append(air, flight{w: w, text: txt, to: to})
				}
				// Deliver: mostly promptly, in a random order; nothing is
				// left in the air for more than ~12 steps.
				for i := 0; i < len(air); {
					air[i].age++
					if air[i].age > 12 || r.IntN(3) != 0 {
						deliver(i)
					} else {
						i++
					}
				}
				if step%37 == 0 {
					for _, e := range []*endpoint{a, b} {
						var s Session
						if err := json.Unmarshal(mustJSON(t, e.sess), &s); err != nil {
							t.Fatal(err)
						}
						e.sess = &s
					}
				}
			}
			for len(air) > 0 {
				deliver(0)
			}
			ml, fr := a.sess.PQEpochs()
			if st := a.sess.PQStalled() + b.sess.PQStalled(); st != "" {
				t.Fatalf("PQ ratchet stalled: %s", st)
			}
			if ml < 5 || fr < 5 {
				t.Fatalf("PQ ratchets barely advanced: mlkem=%d frodo=%d", ml, fr)
			}
			t.Logf("delivered %d (+%d duplicates), ML-KEM epochs %d, FrodoKEM epochs %d", delivered, dups, ml, fr)
		})
	}
}

// FuzzSessionOffer: whatever a client sends as an offer, the relay either
// answers it or refuses it. FuzzSessionAnswer: the same for what a device
// gets back.
func FuzzSessionOffer(f *testing.F) {
	offer, err := NewSessionOffer()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(offer.Public())
	f.Add([]byte{})
	f.Add(offer.Public()[:40])
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3})
	f.Fuzz(func(t *testing.T, raw []byte) {
		answer, secret, err := AnswerSession(raw, []byte("bind"))
		if err != nil {
			if !errors.Is(err, ErrSession) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if len(raw) != SessionOfferSize() || len(secret) != SessionKeySize || len(answer) == 0 {
			t.Fatalf("answered an offer of %d bytes with %d and a secret of %d", len(raw), len(answer), len(secret))
		}
	})
}

func FuzzSessionAnswer(f *testing.F) {
	offer, err := NewSessionOffer()
	if err != nil {
		f.Fatal(err)
	}
	answer, want, err := AnswerSession(offer.Public(), []byte("bind"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(answer)
	f.Add([]byte{})
	f.Add(answer[:100])
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3})
	f.Fuzz(func(t *testing.T, raw []byte) {
		secret, err := offer.Open(raw, []byte("bind"))
		if err != nil {
			if !errors.Is(err, ErrSession) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		// Only the true answer gives the true secret.
		if bytes.Equal(secret, want) != bytes.Equal(raw, answer) {
			t.Fatal("another answer gave the same secret, or the same answer another one")
		}
	})
}
