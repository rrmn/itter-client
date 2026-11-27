package pqc

import "errors"

// Systematic Reed-Solomon erasure code over GF(2^16), as recommended by the
// ML-KEM Braid specification. A message is cut into k chunks; chunk i < k is
// the plain data, chunk i >= k is the interpolating polynomial (one per
// 16-bit lane) evaluated at x = i. Any k distinct chunks recover the message,
// so the PQ ratchet keeps making progress when some messages are lost.

const gfPoly = 0x1100B // x^16 + x^12 + x^3 + x + 1 (primitive)

var (
	gfExp [2 * 65535]uint16
	gfLog [65536]uint16
)

func init() {
	x := uint32(1)
	for i := 0; i < 65535; i++ {
		gfExp[i] = uint16(x)
		gfLog[x] = uint16(i)
		x <<= 1
		if x&0x10000 != 0 {
			x ^= gfPoly
		}
	}
	for i := 65535; i < len(gfExp); i++ {
		gfExp[i] = gfExp[i-65535]
	}
}

func gfMul(a, b uint16) uint16 {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfDiv(a, b uint16) uint16 {
	if a == 0 {
		return 0
	}
	if b == 0 {
		panic("gf: division by zero")
	}
	return gfExp[int(gfLog[a])+65535-int(gfLog[b])]
}

// lagrange returns c_j such that p(x) = sum_j c_j * p(xs[j]) for every
// polynomial p of degree < len(xs). xs must be distinct.
func lagrange(x uint16, xs []uint16) []uint16 {
	c := make([]uint16, len(xs))
	for j, xj := range xs {
		if x == xj {
			clear(c)
			c[j] = 1
			return c
		}
	}
	for j, xj := range xs {
		num, den := uint16(1), uint16(1)
		for m, xm := range xs {
			if m == j {
				continue
			}
			num = gfMul(num, x^xm)
			den = gfMul(den, xj^xm)
		}
		c[j] = gfDiv(num, den)
	}
	return c
}

func numChunks(size, chunk int) int { return (size + chunk - 1) / chunk }

// rsEncoder emits codewords of one message (serialisable state).
type rsEncoder struct {
	Data  []byte `json:"d"` // zero-padded to a multiple of Chunk
	Chunk int    `json:"c"`
	Next  uint32 `json:"n"`
}

func newRSEncoder(msg []byte, chunk int) *rsEncoder {
	k := numChunks(len(msg), chunk)
	data := make([]byte, k*chunk)
	copy(data, msg)
	return &rsEncoder{Data: data, Chunk: chunk}
}

// next returns the next codeword. After 65536 codewords it starts over with
// the parity codewords (distinct indices are what matters to the decoder).
func (e *rsEncoder) next() (uint16, []byte) {
	k := len(e.Data) / e.Chunk
	if e.Next > 0xFFFF {
		e.Next = uint32(k)
	}
	idx := uint16(e.Next)
	e.Next++
	return idx, e.codeword(idx)
}

func (e *rsEncoder) codeword(idx uint16) []byte {
	k := len(e.Data) / e.Chunk
	if int(idx) < k {
		return append([]byte(nil), e.Data[int(idx)*e.Chunk:(int(idx)+1)*e.Chunk]...)
	}
	xs := make([]uint16, k)
	for i := range xs {
		xs[i] = uint16(i)
	}
	c := lagrange(idx, xs)
	out := make([]byte, e.Chunk)
	for lane := 0; lane < e.Chunk/2; lane++ {
		var acc uint16
		for j := 0; j < k; j++ {
			off := j*e.Chunk + 2*lane
			acc ^= gfMul(c[j], uint16(e.Data[off])<<8|uint16(e.Data[off+1]))
		}
		out[2*lane], out[2*lane+1] = byte(acc>>8), byte(acc)
	}
	return out
}

// rsDecoder collects codewords of a message of known size.
type rsDecoder struct {
	Size  int               `json:"s"`
	Chunk int               `json:"c"`
	Got   map[uint16][]byte `json:"g"`
}

var errChunk = errors.New("pqc: bad erasure-code chunk")

func newRSDecoder(size, chunk int) *rsDecoder {
	return &rsDecoder{Size: size, Chunk: chunk, Got: map[uint16][]byte{}}
}

func (d *rsDecoder) add(idx uint16, chunk []byte) error {
	if len(chunk) != d.Chunk {
		return errChunk
	}
	if _, dup := d.Got[idx]; !dup && !d.complete() {
		d.Got[idx] = append([]byte(nil), chunk...)
	}
	return nil
}

func (d *rsDecoder) complete() bool { return len(d.Got) >= numChunks(d.Size, d.Chunk) }

func (d *rsDecoder) message() ([]byte, error) {
	k := numChunks(d.Size, d.Chunk)
	if len(d.Got) < k {
		return nil, errChunk
	}
	// Prefer systematic chunks, then fill up with parity chunks.
	xs := make([]uint16, 0, k)
	for i := 0; i < k; i++ {
		if _, ok := d.Got[uint16(i)]; ok {
			xs = append(xs, uint16(i))
		}
	}
	for idx := range d.Got {
		if len(xs) == k {
			break
		}
		if int(idx) >= k {
			xs = append(xs, idx)
		}
	}
	out := make([]byte, k*d.Chunk)
	for t := 0; t < k; t++ {
		if cw, ok := d.Got[uint16(t)]; ok {
			copy(out[t*d.Chunk:], cw)
			continue
		}
		c := lagrange(uint16(t), xs)
		for lane := 0; lane < d.Chunk/2; lane++ {
			var acc uint16
			for j, x := range xs {
				cw := d.Got[x]
				acc ^= gfMul(c[j], uint16(cw[2*lane])<<8|uint16(cw[2*lane+1]))
			}
			out[t*d.Chunk+2*lane], out[t*d.Chunk+2*lane+1] = byte(acc>>8), byte(acc)
		}
	}
	return out[:d.Size], nil
}
