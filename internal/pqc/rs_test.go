package pqc

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand/v2"
	"testing"
)

func TestGFIsAField(t *testing.T) {
	seen := map[uint16]bool{}
	for i := 0; i < 65535; i++ {
		v := gfExp[i]
		if v == 0 || seen[v] {
			t.Fatalf("x is not a generator: repeat at %d", i)
		}
		seen[v] = true
	}
	for _, a := range []uint16{1, 2, 3, 0x1234, 0xFFFF} {
		for _, b := range []uint16{1, 7, 0x8000, 0xABCD} {
			if gfDiv(gfMul(a, b), b) != a {
				t.Fatalf("mul/div mismatch for %x %x", a, b)
			}
		}
	}
}

func TestErasureCodeRecoversFromAnyKChunks(t *testing.T) {
	r := mrand.New(mrand.NewPCG(1, 2))
	for _, tc := range []struct{ size, chunk int }{{1216, 256}, {1120, 256}, {15664, 2048}, {15776, 2048}, {100, 32}, {64, 64}} {
		msg := make([]byte, tc.size)
		rand.Read(msg)
		for trial := 0; trial < 20; trial++ {
			enc := newRSEncoder(msg, tc.chunk)
			dec := newRSDecoder(tc.size, tc.chunk)
			for !dec.complete() {
				idx, cw := enc.next()
				if r.IntN(3) == 0 { // drop a third of the codewords
					continue
				}
				if err := dec.add(idx, cw); err != nil {
					t.Fatal(err)
				}
			}
			got, err := dec.message()
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("size %d chunk %d: wrong reconstruction", tc.size, tc.chunk)
			}
		}
	}
}
