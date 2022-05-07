// Package polyval implements POLYVAL per RFC 8452.
//
// The universal hash function POLYVAL is the byte-wise reverse
// of GHASH.
//
// [rfc8452]: https://datatracker.ietf.org/doc/html/rfc8452#section-3
// [gueron]: https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
package polyval

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ericlagergren/subtle"
)

//go:generate go run github.com/ericlagergren/polyval/internal/cmd/gen ctmul

const (
	// Size is the size in bytes of a POLYVAL checksum.
	Size = 16
)

// Sum returns the POLYVAL hash of data.
func Sum(key, data []byte) [Size]byte {
	var p Polyval
	if err := p.Init(key); err != nil {
		panic(err)
	}
	p.Update(data)
	return *(*[Size]byte)(p.Sum(nil))
}

// Polyval is an implementation of POLYVAL.
//
// It operates similar to the standard library's Hash interface,
// but only accepts full blocks. Callers should pad the input
// accordingly.
//
// POLYVAL is similar to GHASH. It operates in GF(2^128) defined
// by the irreducible polynomial
//
//    x^128 + x^127 + x^126 + x^121 + 1.
//
// The field has characteristic 2, so addition is performed with
// XOR. Multiplication is polynomial multiplication reduced
// modulo the polynomial.
//
// For more information on POLYVAL, see [rfc8452].
type Polyval struct {
	// Make Polyval non-comparable to prevent accidental
	// non-constant time comparisons.
	_ [0]func()
	// h is the hash key.
	h fieldElement
	// y is the running state.
	y fieldElement
	// pow is a pre-computed table of powers of h for writing
	// groups of eight blocks.
	pow [8]fieldElement
}

var (
	_ encoding.BinaryMarshaler
	_ encoding.BinaryUnmarshaler
)

// New creates a Polyval.
//
// The key must be exactly 16 bytes long and cannot be all zero.
func New(key []byte) (*Polyval, error) {
	var p Polyval
	if err := p.Init(key); err != nil {
		return nil, err
	}
	return &p, nil
}

// Init initializes a Polyval.
//
// The key must be exactly 16 bytes long and cannot be all zero.
func (p *Polyval) Init(key []byte) error {
	if len(key) != 16 {
		return fmt.Errorf("invalid key size: %d", len(key))
	}
	if subtle.ConstantTimeBigEndianZero(key) == 1 {
		return errors.New("the zero key is invalid")
	}

	p.h.setBytes(key)
	p.pow[len(p.pow)-1] = p.h
	for i := len(p.pow) - 2; i >= 0; i-- {
		p.pow[i] = p.h
		polymul(&p.pow[i], &p.pow[i+1])
	}
	return nil
}

// Size returns the size of a POLYVAL digest.
func (p *Polyval) Size() int {
	return Size
}

// BlockSize returns the size of a POLYVAL block.
func (p *Polyval) BlockSize() int {
	return 16
}

// Reset sets the hash to its original state.
func (p *Polyval) Reset() {
	p.y = fieldElement{}
}

// Update writes one or more blocks to the running hash.
//
// If len(block) is not divisible by BlockSize, Update will panic.
func (p *Polyval) Update(blocks []byte) {
	if len(blocks)%16 != 0 {
		panic("polyval: invalid input length")
	}
	polymulBlocks(&p.y, &p.pow, blocks)
}

// Sum appends the current hash to b and returns the resulting
// slice.
//
// It does not change the underlying hash state.
func (p *Polyval) Sum(b []byte) []byte {
	ret, out := subtle.SliceForAppend(b, 16)
	binary.LittleEndian.PutUint64(out[0:8], p.y.lo)
	binary.LittleEndian.PutUint64(out[8:16], p.y.hi)
	return ret
}

// MarshalBinary implements BinaryMarshaler.
//
// It does not return an error.
func (p *Polyval) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 16*(2+len(p.pow)))
	binary.LittleEndian.PutUint64(buf[0:], p.h.lo)
	binary.LittleEndian.PutUint64(buf[8:], p.h.hi)
	binary.LittleEndian.PutUint64(buf[16:], p.y.lo)
	binary.LittleEndian.PutUint64(buf[24:], p.y.hi)
	for i, x := range p.pow {
		binary.LittleEndian.PutUint64(buf[32+(i*16):], x.lo)
		binary.LittleEndian.PutUint64(buf[40+(i*16):], x.hi)
	}
	return buf, nil
}

// Unmarshalbinary implements BinaryUnmarshaler.
//
// data must be exactly 160 bytes.
func (p *Polyval) UnmarshalBinary(data []byte) error {
	if len(data) != 16*(2+len(p.pow)) {
		return fmt.Errorf("invalid data size: %d", len(data))
	}
	p.h.lo = binary.LittleEndian.Uint64(data[0:8])
	p.h.hi = binary.LittleEndian.Uint64(data[8:16])
	p.y.lo = binary.LittleEndian.Uint64(data[16:24])
	p.y.hi = binary.LittleEndian.Uint64(data[24:32])
	for i, x := range p.pow {
		x.lo = binary.LittleEndian.Uint64(data[32+(i*16):])
		x.hi = binary.LittleEndian.Uint64(data[40+(i*16):])
		p.pow[i] = x
	}
	return nil
}

func polymulGeneric(acc, key *fieldElement) {
	x, y := key, acc
	// We perform schoolbook multiplication of x and y:
	//
	// (x1,x0)*(y1,y0) = (x1*y1) + (x1*y0 + x0*y1) + (x0*y0)
	//                      H         M       M         L
	//
	// The middle result (M) can be simplified with Karatsuba
	// multiplication:
	//
	// (x1*y0 + x0*y1)  = (x1+x0) * (y1+x0) + (x1*y1) + (x0*y0)
	//        M                                  H         L
	//
	// This requires one less 64-bit multiplication and reuses
	// the existing results H and L. (H and L are added to M in
	// the montgomery reduction; see x1 and x2.)
	//
	// This gives us a 256-bit product, X.
	//
	// Use the "Shift-XOR reflected reduction" method to reduce
	// it modulo x^128 + x^127 + x^126 + x^121 + 1.
	//
	// This is faster than Gueron's "Fast reduction ..." method
	// because Go doesn't have CMUL/PMULL intrinsics.
	//
	// See [gueron] page 17-19.
	h1, h0 := ctmul(x.hi, y.hi)           // H
	l1, l0 := ctmul(x.lo, y.lo)           // L
	m1, m0 := ctmul(x.hi^x.lo, y.hi^y.lo) // M

	m0 ^= l0 ^ h0
	m1 ^= l1 ^ h1

	l1 ^= m0 ^ (l0 << 63) ^ (l0 << 62) ^ (l0 << 57)
	h0 ^= l0 ^ (l0 >> 1) ^ (l0 >> 2) ^ (l0 >> 7)
	h0 ^= m1 ^ (l1 << 63) ^ (l1 << 62) ^ (l1 << 57)
	h1 ^= l1 ^ (l1 >> 1) ^ (l1 >> 2) ^ (l1 >> 7)

	y.hi = h1
	y.lo = h0
}

func polymulBlocksGeneric(acc *fieldElement, pow *[8]fieldElement, blocks []byte) {
	for (len(blocks)/16)%8 != 0 {
		acc.lo ^= binary.LittleEndian.Uint64(blocks[0:8])
		acc.hi ^= binary.LittleEndian.Uint64(blocks[8:16])
		polymulGeneric(acc, &pow[len(pow)-1])
		blocks = blocks[16:]
	}

	const (
		wide = 16 * len(pow)
	)
	for len(blocks) >= wide {
		var h1, h0, l1, l0, m1, m0 uint64
		for i, x := range pow {
			var y fieldElement
			y.setBytes(blocks[:16])
			if i == 0 {
				y.lo ^= acc.lo
				y.hi ^= acc.hi
			}

			t1, t0 := ctmul(x.hi, y.hi)
			h1 ^= t1
			h0 ^= t0

			t1, t0 = ctmul(x.lo, y.lo)
			l1 ^= t1
			l0 ^= t0

			t1, t0 = ctmul(x.hi^x.lo, y.hi^y.lo)
			m1 ^= t1
			m0 ^= t0

			blocks = blocks[16:]
		}

		m0 ^= l0 ^ h0
		m1 ^= l1 ^ h1

		l1 ^= m0 ^ (l0 << 63) ^ (l0 << 62) ^ (l0 << 57)
		h0 ^= l0 ^ (l0 >> 1) ^ (l0 >> 2) ^ (l0 >> 7)
		h0 ^= m1 ^ (l1 << 63) ^ (l1 << 62) ^ (l1 << 57)
		h1 ^= l1 ^ (l1 >> 1) ^ (l1 >> 2) ^ (l1 >> 7)

		acc.hi = h1
		acc.lo = h0
	}
}

// fieldElement is a little-endian element in GF(2^128).
type fieldElement struct {
	lo, hi uint64
}

func (f fieldElement) String() string {
	return fmt.Sprintf("%#0.16x%0.16x", f.hi, f.lo)
}

// setBytes sets z to the little-endian element p.
func (z *fieldElement) setBytes(p []byte) {
	z.lo = binary.LittleEndian.Uint64(p[0:8])
	z.hi = binary.LittleEndian.Uint64(p[8:16])
}
