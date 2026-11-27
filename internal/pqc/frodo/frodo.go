// Package frodo implements FrodoKEM (SHAKE variants) for the parameter sets
// FrodoKEM-640, FrodoKEM-976 and FrodoKEM-1344, as specified in the FrodoKEM
// NIST round-3 submission (the "eFrodoKEM" construction of the ISO draft).
//
// FrodoKEM is plain (unstructured) LWE: unlike ML-KEM it has no polynomial
// ring, so it stays secure even if ring/module-lattice structure is broken.
// That is why itter uses it as the load-bearing post-quantum KEM.
//
// The code follows the FrodoKEM reference implementation
// (github.com/microsoft/PQCrypto-LWEKE, MIT license) and the FrodoKEM-640
// implementation in github.com/cloudflare/circl (BSD-3-Clause), generalised
// to all three parameter sets. It is validated against the official KAT
// files in frodo_kat_test.go.
package frodo

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
)

const (
	nbar      = 8
	seedASize = 16
)

// Params describes one FrodoKEM-SHAKE parameter set.
type Params struct {
	name     string
	n        int
	logQ     uint
	b        uint // extracted bits
	lenSec   int  // CRYPTO_BYTES: len(s) = len(seedSE) = len(k) = len(pkh) = len(ss)
	lenMu    int
	cdf      []uint16
	shake256 bool // KEM hash: SHAKE128 for 640, SHAKE256 for 976 and 1344
}

var (
	// FrodoKEM640 is FrodoKEM-640-SHAKE (NIST level 1).
	FrodoKEM640 = &Params{name: "FrodoKEM-640-SHAKE", n: 640, logQ: 15, b: 2, lenSec: 16, lenMu: 16,
		cdf: []uint16{4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767}}
	// FrodoKEM976 is FrodoKEM-976-SHAKE (NIST level 3).
	FrodoKEM976 = &Params{name: "FrodoKEM-976-SHAKE", n: 976, logQ: 16, b: 3, lenSec: 24, lenMu: 24, shake256: true,
		cdf: []uint16{5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767}}
	// FrodoKEM1344 is FrodoKEM-1344-SHAKE (NIST level 5).
	FrodoKEM1344 = &Params{name: "FrodoKEM-1344-SHAKE", n: 1344, logQ: 16, b: 4, lenSec: 32, lenMu: 32, shake256: true,
		cdf: []uint16{9142, 23462, 30338, 32361, 32725, 32765, 32767}}
)

var (
	errSize = errors.New("frodo: wrong input size")
)

func (p *Params) Name() string        { return p.name }
func (p *Params) PublicKeySize() int  { return seedASize + p.matBSize() }
func (p *Params) PrivateKeySize() int { return p.lenSec + p.PublicKeySize() + 2*p.n*nbar + p.lenSec }
func (p *Params) CiphertextSize() int { return p.matBSize() + p.matCSize() }
func (p *Params) SharedKeySize() int  { return p.lenSec }
func (p *Params) KeySeedSize() int    { return 2*p.lenSec + seedASize }
func (p *Params) EncapsSeedSize() int { return p.lenMu }
func (p *Params) matBSize() int       { return int(p.logQ) * p.n * nbar / 8 }
func (p *Params) matCSize() int       { return int(p.logQ) * nbar * nbar / 8 }
func (p *Params) mask() uint16        { return uint16((1 << p.logQ) - 1) }

func (p *Params) shake() *sha3.SHAKE {
	if p.shake256 {
		return sha3.NewSHAKE256()
	}
	return sha3.NewSHAKE128()
}

func (p *Params) hash(out []byte, in ...[]byte) {
	h := p.shake()
	for _, b := range in {
		h.Write(b)
	}
	h.Read(out)
}

// GenerateKey returns a fresh key pair.
func (p *Params) GenerateKey() (pk, sk []byte, err error) {
	seed := make([]byte, p.KeySeedSize())
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	pk, sk = p.NewKeyFromSeed(seed)
	clear(seed)
	return pk, sk, nil
}

// NewKeyFromSeed derives a key pair from seed = s || seedSE || z.
func (p *Params) NewKeyFromSeed(seed []byte) (pk, sk []byte) {
	if len(seed) != p.KeySeedSize() {
		panic(errSize)
	}
	n := p.n
	s := seed[:p.lenSec]
	seedSE := seed[p.lenSec : 2*p.lenSec]
	z := seed[2*p.lenSec:]

	pk = make([]byte, p.PublicKeySize())
	seedA := pk[:seedASize]
	p.hash(seedA, z)

	// S^T (nbar x n) and E (n x nbar) from SHAKE(0x5F || seedSE).
	r := make([]byte, 2*2*n*nbar)
	p.hash(r, []byte{0x5F}, seedSE)
	ST := make([]uint16, n*nbar)
	E := make([]uint16, n*nbar)
	for i := range ST {
		ST[i] = uint16(r[2*i]) | uint16(r[2*i+1])<<8
	}
	for i := range E {
		E[i] = uint16(r[2*(n*nbar+i)]) | uint16(r[2*(n*nbar+i)+1])<<8
	}
	clear(r)
	p.sample(ST)
	p.sample(E)

	B := make([]uint16, n*nbar)
	p.mulAddASPlusE(B, seedA, ST, E)
	clear(E)
	p.pack(pk[seedASize:], B)

	sk = make([]byte, p.PrivateKeySize())
	off := 0
	off += copy(sk[off:], s)
	off += copy(sk[off:], pk)
	for _, v := range ST {
		sk[off] = byte(v)
		sk[off+1] = byte(v >> 8)
		off += 2
	}
	p.hash(sk[off:off+p.lenSec], pk)
	clear(ST)
	return pk, sk
}

// Encapsulate generates a shared secret and its ciphertext for pk.
func (p *Params) Encapsulate(pk []byte) (ct, ss []byte, err error) {
	mu := make([]byte, p.lenMu)
	if _, err := rand.Read(mu); err != nil {
		return nil, nil, err
	}
	defer clear(mu)
	return p.EncapsulateDeterministic(pk, mu)
}

// EncapsulateDeterministic is Encapsulate with caller-supplied randomness mu.
// It exists for known-answer tests; use Encapsulate otherwise.
func (p *Params) EncapsulateDeterministic(pk, mu []byte) (ct, ss []byte, err error) {
	if len(pk) != p.PublicKeySize() || len(mu) != p.lenMu {
		return nil, nil, errSize
	}
	n := p.n
	pkh := make([]byte, p.lenSec)
	p.hash(pkh, pk)
	g2 := make([]byte, 2*p.lenSec)
	p.hash(g2, pkh, mu)
	seedSE, k := g2[:p.lenSec], g2[p.lenSec:]
	defer clear(g2)

	Sp, Ep, Epp := p.sampleSpEpEpp(seedSE)
	defer clear(Sp)
	defer clear(Ep)
	defer clear(Epp)

	Bp := make([]uint16, nbar*n)
	p.mulAddSAPlusE(Bp, Sp, pk[:seedASize], Ep)

	B := make([]uint16, n*nbar)
	p.unpack(B, pk[seedASize:])
	V := make([]uint16, nbar*nbar)
	p.mulAddSBPlusE(V, Sp, B, Epp)
	defer clear(V)

	C := make([]uint16, nbar*nbar)
	p.encode(C, mu)
	for i := range C {
		C[i] = (C[i] + V[i]) & p.mask()
	}

	ct = make([]byte, p.CiphertextSize())
	p.pack(ct[:p.matBSize()], Bp)
	p.pack(ct[p.matBSize():], C)

	ss = make([]byte, p.lenSec)
	p.hash(ss, ct, k)
	return ct, ss, nil
}

// Decapsulate recovers the shared secret from ct. Invalid ciphertexts yield a
// pseudo-random secret (implicit rejection), never an error.
func (p *Params) Decapsulate(sk, ct []byte) ([]byte, error) {
	if len(sk) != p.PrivateKeySize() || len(ct) != p.CiphertextSize() {
		return nil, errSize
	}
	n := p.n
	s := sk[:p.lenSec]
	pk := sk[p.lenSec : p.lenSec+p.PublicKeySize()]
	sOff := p.lenSec + p.PublicKeySize()
	ST := make([]uint16, n*nbar)
	for i := range ST {
		ST[i] = uint16(sk[sOff+2*i]) | uint16(sk[sOff+2*i+1])<<8
	}
	defer clear(ST)
	pkh := sk[sOff+2*n*nbar:]

	Bp := make([]uint16, nbar*n)
	C := make([]uint16, nbar*nbar)
	p.unpack(Bp, ct[:p.matBSize()])
	p.unpack(C, ct[p.matBSize():])

	// W = C - Bp*S, mu' = decode(W)
	W := make([]uint16, nbar*nbar)
	p.mulBS(W, Bp, ST)
	for i := range W {
		W[i] = (C[i] - W[i]) & p.mask()
	}
	mu := make([]byte, p.lenMu)
	p.decode(mu, W)
	defer clear(mu)

	g2 := make([]byte, 2*p.lenSec)
	p.hash(g2, pkh, mu)
	seedSE, kp := g2[:p.lenSec], g2[p.lenSec:]
	defer clear(g2)

	Sp, Ep, Epp := p.sampleSpEpEpp(seedSE)
	defer clear(Sp)
	defer clear(Ep)
	defer clear(Epp)

	BBp := make([]uint16, nbar*n)
	p.mulAddSAPlusE(BBp, Sp, pk[:seedASize], Ep)
	for i := range BBp {
		BBp[i] &= p.mask()
	}
	B := make([]uint16, n*nbar)
	p.unpack(B, pk[seedASize:])
	p.mulAddSBPlusE(W, Sp, B, Epp)
	CC := make([]uint16, nbar*nbar)
	p.encode(CC, mu)
	for i := range CC {
		CC[i] = (CC[i] + W[i]) & p.mask()
	}

	// Constant-time: ss = F(ct || k') if re-encryption matches, else F(ct || s).
	ok := ctEqualU16(Bp, BBp) & ctEqualU16(C, CC)
	kk := make([]byte, p.lenSec)
	copy(kk, s)
	subtle.ConstantTimeCopy(ok, kk, kp)
	ss := make([]byte, p.lenSec)
	p.hash(ss, ct, kk)
	clear(kk)
	return ss, nil
}

func (p *Params) sampleSpEpEpp(seedSE []byte) (Sp, Ep, Epp []uint16) {
	n := p.n
	r := make([]byte, 2*(2*n+nbar)*nbar)
	p.hash(r, []byte{0x96}, seedSE)
	all := make([]uint16, (2*n+nbar)*nbar)
	for i := range all {
		all[i] = uint16(r[2*i]) | uint16(r[2*i+1])<<8
	}
	clear(r)
	p.sample(all)
	return all[:n*nbar], all[n*nbar : 2*n*nbar], all[2*n*nbar:]
}

// sample maps uniform 16-bit values to the FrodoKEM error distribution in
// constant time (inverse transform sampling over the CDF table).
func (p *Params) sample(s []uint16) {
	for i := range s {
		var e uint16
		sign := s[i] & 1
		u := s[i] >> 1
		for j := 0; j < len(p.cdf)-1; j++ {
			e += (p.cdf[j] - u) >> 15
		}
		s[i] = ((-sign) ^ e) + sign
	}
}

// aRow writes row i of A (n values) generated by SHAKE128(<i>_LE16 || seedA).
func (p *Params) aRow(row []uint16, buf []byte, seedA []byte, i int) {
	in := make([]byte, 2+seedASize)
	in[0], in[1] = byte(i), byte(i>>8)
	copy(in[2:], seedA)
	h := sha3.NewSHAKE128()
	h.Write(in)
	h.Read(buf)
	for j := range row {
		row[j] = uint16(buf[2*j]) | uint16(buf[2*j+1])<<8
	}
}

// out (n x nbar) = A*S + E, with S given transposed (nbar x n).
func (p *Params) mulAddASPlusE(out []uint16, seedA []byte, ST, E []uint16) {
	n := p.n
	row := make([]uint16, n)
	buf := make([]byte, 2*n)
	for i := 0; i < n; i++ {
		p.aRow(row, buf, seedA, i)
		for k := 0; k < nbar; k++ {
			sum := E[i*nbar+k]
			sk := ST[k*n : (k+1)*n]
			for j := 0; j < n; j++ {
				sum += row[j] * sk[j]
			}
			out[i*nbar+k] = sum
		}
	}
}

// out (nbar x n) = S'*A + E', S' is nbar x n.
func (p *Params) mulAddSAPlusE(out []uint16, Sp []uint16, seedA []byte, Ep []uint16) {
	n := p.n
	copy(out, Ep)
	row := make([]uint16, n)
	buf := make([]byte, 2*n)
	for j := 0; j < n; j++ { // row j of A
		p.aRow(row, buf, seedA, j)
		for k := 0; k < nbar; k++ {
			s := Sp[k*n+j]
			o := out[k*n : (k+1)*n]
			for i := 0; i < n; i++ {
				o[i] += row[i] * s
			}
		}
	}
}

// out (nbar x nbar) = S'*B + E”; S' is nbar x n, B is n x nbar.
func (p *Params) mulAddSBPlusE(out []uint16, Sp, B, Epp []uint16) {
	n := p.n
	for k := 0; k < nbar; k++ {
		for i := 0; i < nbar; i++ {
			sum := Epp[k*nbar+i]
			for j := 0; j < n; j++ {
				sum += Sp[k*n+j] * B[j*nbar+i]
			}
			out[k*nbar+i] = sum & p.mask()
		}
	}
}

// out (nbar x nbar) = B'*S; B' is nbar x n, S given transposed (nbar x n).
func (p *Params) mulBS(out []uint16, Bp, ST []uint16) {
	n := p.n
	for i := 0; i < nbar; i++ {
		for j := 0; j < nbar; j++ {
			var sum uint16
			for k := 0; k < n; k++ {
				sum += Bp[i*n+k] * ST[j*n+k]
			}
			out[i*nbar+j] = sum & p.mask()
		}
	}
}

// pack writes the low logQ bits of each value, most significant bit first.
func (p *Params) pack(out []byte, in []uint16) {
	clear(out)
	var acc uint32
	var bits uint
	o := 0
	for _, v := range in {
		acc = acc<<p.logQ | uint32(v&p.mask())
		bits += p.logQ
		for bits >= 8 {
			bits -= 8
			out[o] = byte(acc >> bits)
			o++
		}
		acc &= (1 << bits) - 1
	}
}

func (p *Params) unpack(out []uint16, in []byte) {
	var acc uint32
	var bits uint
	o := 0
	for _, b := range in {
		acc = acc<<8 | uint32(b)
		bits += 8
		if bits >= p.logQ {
			bits -= p.logQ
			out[o] = uint16(acc>>bits) & p.mask()
			o++
			acc &= (1 << bits) - 1
		}
	}
}

// encode maps mu (b bits per entry, little-endian within each b-byte word)
// onto the nbar x nbar matrix, scaled by q/2^b.
func (p *Params) encode(out []uint16, mu []byte) {
	pos := 0
	for w := 0; w < nbar*nbar/8; w++ {
		var t uint64
		for j := 0; j < int(p.b); j++ {
			t |= uint64(mu[w*int(p.b)+j]) << (8 * j)
		}
		for j := 0; j < 8; j++ {
			out[pos] = uint16(t&((1<<p.b)-1)) << (p.logQ - p.b)
			t >>= p.b
			pos++
		}
	}
}

func (p *Params) decode(mu []byte, in []uint16) {
	pos := 0
	for w := 0; w < nbar*nbar/8; w++ {
		var t uint64
		for j := 0; j < 8; j++ {
			v := ((in[pos] & p.mask()) + (1 << (p.logQ - p.b - 1))) >> (p.logQ - p.b)
			t |= uint64(v&((1<<p.b)-1)) << (int(p.b) * j)
			pos++
		}
		for j := 0; j < int(p.b); j++ {
			mu[w*int(p.b)+j] = byte(t >> (8 * j))
		}
	}
}

// ctEqualU16 returns 1 if a == b, 0 otherwise, in constant time.
func ctEqualU16(a, b []uint16) int {
	var v uint16
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return int(1 - ((v | -v) >> 15))
}
