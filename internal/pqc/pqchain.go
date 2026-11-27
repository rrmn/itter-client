package pqc

import (
	"errors"
	"fmt"
	"sort"
)

// PQChain turns the braid's epoch secrets into per-message keys (SPQR's
// symmetric layer). Each epoch gets a send chain and a receive chain; a few
// epochs before the current sending epoch are kept so late messages still
// decrypt.

const (
	pqMaxSkip    = 1000 // max gap inside one epoch chain
	pqMaxSkipped = 2000 // max stored skipped keys per chain
	// pqKeepEpochs is how many epochs before the current sending epoch stay
	// available for RECEIVING, so a message that was overtaken by a few
	// ratchet steps still decrypts (the Double Ratchet keeps its skipped
	// keys for about as long). Sending never uses an old epoch.
	pqKeepEpochs = 3
)

type pqLink struct {
	Epoch  uint64 `json:"e"`
	SendCK []byte `json:"sck,omitempty"`
	SendN  uint32 `json:"sn"`
	RecvCK []byte `json:"rck,omitempty"`
	RecvN  uint32 `json:"rn"`
}

// PQChain is serialisable.
type PQChain struct {
	Initiator bool              `json:"i"`
	CurEpoch  uint64            `json:"ce"`
	SendEpoch uint64            `json:"se"`
	NextRoot  []byte            `json:"nr"`
	Links     []*pqLink         `json:"l"`
	Skipped   map[string][]byte `json:"sk,omitempty"`
}

var errPQKey = errors.New("pqc: PQ message key unavailable")

func newPQChain(p *braidParams, sk []byte, initiator bool) *PQChain {
	out := kdf(nil, sk, p.label+"/chain-start", 96)
	c := &PQChain{Initiator: initiator, NextRoot: out[:32]}
	c.Links = []*pqLink{c.link(0, out[32:64], out[64:96])}
	return c
}

func (c *PQChain) link(epoch uint64, a2b, b2a []byte) *pqLink {
	if c.Initiator {
		return &pqLink{Epoch: epoch, SendCK: a2b, RecvCK: b2a}
	}
	return &pqLink{Epoch: epoch, SendCK: b2a, RecvCK: a2b}
}

func (c *PQChain) addEpoch(p *braidParams, k *epochKey) error {
	if k.Epoch != c.CurEpoch+1 {
		return fmt.Errorf("pqc: PQ epoch %d out of order (at %d)", k.Epoch, c.CurEpoch)
	}
	out := kdf(c.NextRoot, k.Secret, p.label+"/chain-add-epoch"+be64(k.Epoch), 96)
	c.NextRoot = out[:32]
	c.CurEpoch = k.Epoch
	c.Links = append(c.Links, c.link(k.Epoch, out[32:64], out[64:96]))
	return nil
}

func (c *PQChain) find(epoch uint64) *pqLink {
	for _, l := range c.Links {
		if l.Epoch == epoch {
			return l
		}
	}
	return nil
}

func chainStep(p *braidParams, ck []byte, n uint32) (next, mk []byte) {
	out := kdf(nil, ck, p.label+"/chain-next"+be32(n), 64)
	return out[:32], out[32:]
}

func (c *PQChain) sendKey(p *braidParams, epoch uint64) (uint32, []byte, error) {
	if epoch < c.SendEpoch {
		return 0, nil, errors.New("pqc: PQ sending epoch went backwards")
	}
	if epoch > c.SendEpoch {
		c.SendEpoch = epoch
		// Forget epochs that are too old even for late messages, and never
		// send in an older epoch again.
		var kept []*pqLink
		for _, l := range c.Links {
			if l.Epoch+pqKeepEpochs < epoch {
				c.dropSkipped(l.Epoch)
				continue
			}
			if l.Epoch < epoch {
				l.SendCK = nil
			}
			kept = append(kept, l)
		}
		c.Links = kept
	}
	l := c.find(epoch)
	if l == nil || l.SendCK == nil {
		return 0, nil, errPQKey
	}
	l.SendN++
	var mk []byte
	l.SendCK, mk = chainStep(p, l.SendCK, l.SendN)
	return l.SendN, mk, nil
}

func skipID(epoch uint64, n uint32) string { return fmt.Sprintf("%d:%d", epoch, n) }

func (c *PQChain) recvKey(p *braidParams, epoch uint64, n uint32) ([]byte, error) {
	l := c.find(epoch)
	if l == nil || n == 0 {
		return nil, errPQKey
	}
	if n <= l.RecvN {
		id := skipID(epoch, n)
		mk, ok := c.Skipped[id]
		if !ok {
			return nil, ErrDuplicate // already used, or expired
		}
		delete(c.Skipped, id)
		return mk, nil
	}
	if n-l.RecvN > pqMaxSkip {
		return nil, errors.New("pqc: too many skipped PQ messages")
	}
	if c.Skipped == nil {
		c.Skipped = map[string][]byte{}
	}
	for l.RecvN+1 < n {
		l.RecvN++
		var mk []byte
		l.RecvCK, mk = chainStep(p, l.RecvCK, l.RecvN)
		c.Skipped[skipID(epoch, l.RecvN)] = mk
	}
	c.trimSkipped()
	l.RecvN++
	var mk []byte
	l.RecvCK, mk = chainStep(p, l.RecvCK, l.RecvN)
	return mk, nil
}

func (c *PQChain) dropSkipped(epoch uint64) {
	prefix := fmt.Sprintf("%d:", epoch)
	for id := range c.Skipped {
		if len(id) > len(prefix) && id[:len(prefix)] == prefix {
			delete(c.Skipped, id)
		}
	}
}

// trimSkipped evicts the oldest skipped keys beyond the cap.
func (c *PQChain) trimSkipped() {
	if len(c.Skipped) <= pqMaxSkipped {
		return
	}
	type ent struct {
		e  uint64
		n  uint32
		id string
	}
	var all []ent
	for id := range c.Skipped {
		var e uint64
		var n uint32
		fmt.Sscanf(id, "%d:%d", &e, &n)
		all = append(all, ent{e, n, id})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].e != all[j].e {
			return all[i].e < all[j].e
		}
		return all[i].n < all[j].n
	})
	for _, x := range all[:len(all)-pqMaxSkipped] {
		delete(c.Skipped, x.id)
	}
}
