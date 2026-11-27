package frodo

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"
)

// nistDRBG is the AES-256 CTR DRBG used by the NIST PQC KAT generator
// (randombytes_init / randombytes in rng.c).
type nistDRBG struct {
	key [32]byte
	v   [16]byte
}

func newNISTDRBG(seed *[48]byte) *nistDRBG {
	d := &nistDRBG{}
	d.update(seed[:])
	return d
}

func (d *nistDRBG) incV() {
	for j := 15; j >= 0; j-- {
		if d.v[j] == 0xff {
			d.v[j] = 0
		} else {
			d.v[j]++
			break
		}
	}
}

func (d *nistDRBG) update(provided []byte) {
	var tmp [48]byte
	c, _ := aes.NewCipher(d.key[:])
	for i := 0; i < 3; i++ {
		d.incV()
		c.Encrypt(tmp[16*i:], d.v[:])
	}
	if provided != nil {
		for i := range tmp {
			tmp[i] ^= provided[i]
		}
	}
	copy(d.key[:], tmp[:32])
	copy(d.v[:], tmp[32:])
}

func (d *nistDRBG) fill(x []byte) {
	c, _ := aes.NewCipher(d.key[:])
	var block [16]byte
	for len(x) > 0 {
		d.incV()
		c.Encrypt(block[:], d.v[:])
		n := copy(x, block[:])
		x = x[n:]
	}
	d.update(nil)
}

// katHash regenerates the 100-entry NIST KAT file for p and returns its
// SHA-256, which must equal the hash of the official .rsp file.
func katHash(t *testing.T, p *Params) string {
	var seed [48]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	g := newNISTDRBG(&seed)
	f := sha256.New()
	w := func(h hash.Hash, format string, a ...any) { fmt.Fprintf(h, format, a...) }
	w(f, "# %s\n\n", p.Name())
	kseed := make([]byte, p.KeySeedSize())
	eseed := make([]byte, p.EncapsSeedSize())
	for i := 0; i < 100; i++ {
		g.fill(seed[:])
		w(f, "count = %d\n", i)
		w(f, "seed = %X\n", seed)
		g2 := newNISTDRBG(&seed)
		g2.fill(kseed)
		pk, sk := p.NewKeyFromSeed(kseed)
		g2.fill(eseed)
		ct, ss, err := p.EncapsulateDeterministic(pk, eseed)
		if err != nil {
			t.Fatal(err)
		}
		ss2, err := p.Decapsulate(sk, ct)
		if err != nil || !bytes.Equal(ss, ss2) {
			t.Fatalf("%s: decapsulation mismatch at count %d", p.Name(), i)
		}
		w(f, "pk = %X\n", pk)
		w(f, "sk = %X\n", sk)
		w(f, "ct = %X\n", ct)
		w(f, "ss = %X\n\n", ss)
	}
	return fmt.Sprintf("%x", f.Sum(nil))
}

// SHA-256 of KAT/PQCkemKAT_{19888,31296,43088}_shake.rsp at
// github.com/microsoft/PQCrypto-LWEKE commit 66fc7744c3aae6acfc5fcc587ec7f2cdec48d216.
func TestOfficialKATs(t *testing.T) {
	kats := []struct {
		p    *Params
		want string
	}{
		{FrodoKEM640, "604a10cfc871dfaed9cb5b057c644ab03b16852cea7f39bc7f9831513b5b1cfa"},
		{FrodoKEM976, "32b0ad60047273fb52696f0516acac7ed083e31f5478b416d579ae5e8d8e734c"},
		{FrodoKEM1344, "591adc09a718afbc0ac36e1f57a191e557fe4eec7899e078104b9706b75e2f96"},
	}
	for _, k := range kats {
		t.Run(k.p.Name(), func(t *testing.T) {
			if testing.Short() && k.p != FrodoKEM976 {
				t.Skip("short mode")
			}
			if got := katHash(t, k.p); got != k.want {
				t.Fatalf("KAT hash mismatch:\n got %s\nwant %s", got, k.want)
			}
		})
	}
}

func TestSizes(t *testing.T) {
	for _, c := range []struct {
		p              *Params
		pk, sk, ct, ss int
	}{
		{FrodoKEM640, 9616, 19888, 9720, 16},
		{FrodoKEM976, 15632, 31296, 15744, 24},
		{FrodoKEM1344, 21520, 43088, 21632, 32},
	} {
		if c.p.PublicKeySize() != c.pk || c.p.PrivateKeySize() != c.sk ||
			c.p.CiphertextSize() != c.ct || c.p.SharedKeySize() != c.ss {
			t.Fatalf("%s: wrong sizes", c.p.Name())
		}
	}
}

func TestImplicitRejection(t *testing.T) {
	p := FrodoKEM976
	pk, sk, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, ss, _ := p.Encapsulate(pk)
	ct[5] ^= 1
	ss2, err := p.Decapsulate(sk, ct)
	if err != nil || bytes.Equal(ss, ss2) {
		t.Fatal("tampered ciphertext must decapsulate to an unrelated secret")
	}
}
