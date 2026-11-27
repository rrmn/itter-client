package pqc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strconv"
)

// The classic Double Ratchet (X25519 + HMAC chains), per Signal's
// specification. In the Triple Ratchet it is one of three key sources.

const (
	drMaxSkip    = 1000
	drMaxSkipped = 2000
)

// DR is the serialisable Double Ratchet state.
type DR struct {
	DHsPriv []byte            `json:"dhs_priv"`
	DHsPub  []byte            `json:"dhs_pub"`
	DHr     []byte            `json:"dhr,omitempty"`
	RK      []byte            `json:"rk"`
	CKs     []byte            `json:"cks,omitempty"`
	CKr     []byte            `json:"ckr,omitempty"`
	Ns      uint32            `json:"ns"`
	Nr      uint32            `json:"nr"`
	PN      uint32            `json:"pn"`
	Skipped map[string][]byte `json:"skipped,omitempty"`
	// SkipOrder remembers insertion order so the oldest keys are evicted first.
	SkipOrder []string `json:"skip_order,omitempty"`
	// OldDHr lists the peer's previous ratchet keys, so a late duplicate from
	// a finished chain is recognised instead of being tried as a new ratchet step.
	OldDHr [][]byte `json:"old_dhr,omitempty"`
}

const drKeepOldDH = 16

type drHeader struct {
	DH []byte
	PN uint32
	N  uint32
}

func drKDFRK(rk, dhOut []byte) (newRK, ck []byte) {
	out := kdf(rk, dhOut, "dr/root", 64)
	return out[:32], out[32:]
}

func drKDFCK(ck []byte) (next, mk []byte) {
	h := hmac.New(sha512.New, ck)
	h.Write([]byte{0x01})
	mk = h.Sum(nil)[:32]
	h = hmac.New(sha512.New, ck)
	h.Write([]byte{0x02})
	next = h.Sum(nil)[:32]
	return
}

func drInitAlice(sk, bobDH []byte) (*DR, error) {
	priv, pub, err := x25519Generate()
	if err != nil {
		return nil, err
	}
	d := &DR{DHsPriv: priv, DHsPub: pub, DHr: append([]byte(nil), bobDH...)}
	out, err := x25519(priv, bobDH)
	if err != nil {
		return nil, err
	}
	d.RK, d.CKs = drKDFRK(sk, out)
	zero(out)
	return d, nil
}

func drInitBob(sk, dhPriv, dhPub []byte) *DR {
	return &DR{DHsPriv: append([]byte(nil), dhPriv...), DHsPub: append([]byte(nil), dhPub...),
		RK: append([]byte(nil), sk...)}
}

func (d *DR) sendKey() (drHeader, []byte, error) {
	if d.CKs == nil {
		return drHeader{}, nil, errors.New("pqc: no sending chain yet")
	}
	h := drHeader{DH: d.DHsPub, PN: d.PN, N: d.Ns}
	var mk []byte
	d.CKs, mk = drKDFCK(d.CKs)
	d.Ns++
	return h, mk, nil
}

func drSkipID(dh []byte, n uint32) string {
	return hex.EncodeToString(dh) + ":" + strconv.FormatUint(uint64(n), 10)
}

func (d *DR) recvKey(h drHeader) ([]byte, error) {
	id := drSkipID(h.DH, h.N)
	if mk, ok := d.Skipped[id]; ok {
		delete(d.Skipped, id)
		return mk, nil
	}
	if !bytes.Equal(h.DH, d.DHr) {
		for _, old := range d.OldDHr {
			if bytes.Equal(h.DH, old) {
				return nil, ErrDuplicate // finished chain, key used or discarded
			}
		}
		if err := d.skip(h.PN); err != nil {
			return nil, err
		}
		if err := d.ratchet(h.DH); err != nil {
			return nil, err
		}
	} else if h.N < d.Nr {
		return nil, ErrDuplicate // current chain, key used or discarded
	}
	if err := d.skip(h.N); err != nil {
		return nil, err
	}
	if d.CKr == nil {
		return nil, errors.New("pqc: no receiving chain")
	}
	var mk []byte
	d.CKr, mk = drKDFCK(d.CKr)
	d.Nr++
	return mk, nil
}

func (d *DR) skip(until uint32) error {
	if d.CKr == nil || until <= d.Nr {
		return nil
	}
	if until-d.Nr > drMaxSkip {
		return errors.New("pqc: too many skipped messages")
	}
	if d.Skipped == nil {
		d.Skipped = map[string][]byte{}
	}
	for d.Nr < until {
		var mk []byte
		d.CKr, mk = drKDFCK(d.CKr)
		id := drSkipID(d.DHr, d.Nr)
		d.Skipped[id] = mk
		d.SkipOrder = append(d.SkipOrder, id)
		d.Nr++
	}
	for len(d.Skipped) > drMaxSkipped && len(d.SkipOrder) > 0 {
		delete(d.Skipped, d.SkipOrder[0])
		d.SkipOrder = d.SkipOrder[1:]
	}
	// Drop order entries whose keys were consumed.
	if len(d.SkipOrder) > 2*drMaxSkipped {
		kept := d.SkipOrder[:0]
		for _, id := range d.SkipOrder {
			if _, ok := d.Skipped[id]; ok {
				kept = append(kept, id)
			}
		}
		d.SkipOrder = kept
	}
	return nil
}

func (d *DR) ratchet(theirDH []byte) error {
	if len(d.DHr) > 0 {
		d.OldDHr = append(d.OldDHr, d.DHr)
		if len(d.OldDHr) > drKeepOldDH {
			d.OldDHr = d.OldDHr[len(d.OldDHr)-drKeepOldDH:]
		}
	}
	d.PN = d.Ns
	d.Ns, d.Nr = 0, 0
	d.DHr = append([]byte(nil), theirDH...)
	out, err := x25519(d.DHsPriv, d.DHr)
	if err != nil {
		return err
	}
	d.RK, d.CKr = drKDFRK(d.RK, out)
	zero(out)
	priv, pub, err := x25519Generate()
	if err != nil {
		return err
	}
	d.DHsPriv, d.DHsPub = priv, pub
	out, err = x25519(d.DHsPriv, d.DHr)
	if err != nil {
		return err
	}
	d.RK, d.CKs = drKDFRK(d.RK, out)
	zero(out)
	return nil
}
