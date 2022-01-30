package polyval

import (
	"encoding/binary"
	"fmt"
)

//go:generate go run github.com/ericlagergren/polyval/internal/cmd/gen ctmul

// New creates a Polyval.
//
// The
func New(key []byte) (*Polyval, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("invalid key size: %d", len(key))
	}
	var p Polyval
	p.h.setBytes(key)
	return &p, nil
}

// Polyval is an implementation of POLYVAL.
//
// It operates similar to the standard library's Hash interface,
// but only accepts full blocks.
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
// Fo rmore information, see https://datatracker.ietf.org/doc/html/rfc8452#section-3
type Polyval struct {
	h fieldElement
	y fieldElement
}

// Size returns the size of a POLYVAL digest.
func (p *Polyval) Size() int {
	return 16
}

// BlockSize returns the size of a POLYVAL block.
func (p *Polyval) BlockSize() int {
	return 16
}

// Reset clears the hash to its original state.
func (p *Polyval) Reset() {
	p.y = fieldElement{}
}

// Update writes a block to the running hash.
//
// If len(block) != BlockSize, Update will panic.
func (p *Polyval) Update(block []byte) {
	if len(block) != 16 {
		panic("polyval: invalid block length")
	}
	var x fieldElement
	x.setBytes(block)
	// y = (y+x)*H
	p.y = p.y.xor(x).mul(p.h)
}

// Sum appends the current hash to b and returns the resulting
// slice.
//
// It does not change the underlying hash state.
func (p *Polyval) Sum(b []byte) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], p.y.lo)
	binary.LittleEndian.PutUint64(buf[8:16], p.y.hi)
	return append(b, buf...)
}

// fieldElement is a little-endian element in GF(2^128).
type fieldElement struct {
	hi, lo uint64
}

func (f fieldElement) String() string {
	return fmt.Sprintf("%#0.16x%0.16x", f.hi, f.lo)
}

// setBytes sets z to the little-endian element p.
func (z *fieldElement) setBytes(p []byte) {
	z.lo = binary.LittleEndian.Uint64(p[0:8])
	z.hi = binary.LittleEndian.Uint64(p[8:16])
}

func (x fieldElement) xor(y fieldElement) fieldElement {
	return fieldElement{hi: x.hi ^ y.hi, lo: x.lo ^ y.lo}
}

// mul multiplies the two field elements in GF(2^128) using the
// polynomial x^128 + x^7 + x^2 + x + 1.
func (x fieldElement) mul(y fieldElement) fieldElement {
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
	// Use Shay Gueron's fast montogmery reduction to reduce it
	// modulo x^128 + x^127 + x^126 + x^121 + 1.
	//
	// See https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
	// page 20.
	h1, h0 := ctmul(x.hi, y.hi)           // H
	l1, l0 := ctmul(x.lo, y.lo)           // L
	m1, m0 := ctmul(x.hi^x.lo, y.hi^y.lo) // M

	x0 := l0
	x1 := l1 ^ m0 ^ h0 ^ l0
	x2 := h0 ^ m1 ^ h1 ^ l1
	x3 := h1

	const (
		poly = 0xc200000000000000
	)

	// [A1:A0] = X0 • 0xc200000000000000
	a1, a0 := ctmul(x0, poly)

	// [B1:B0] = [X0 ⊕ A1 : X1 ⊕ A0]
	b1 := x0 ^ a1
	b0 := x1 ^ a0

	// [C1:C0] = B0 • 0xc200000000000000
	c1, c0 := ctmul(b0, poly)

	// [D1:D0] = [B0 ⊕ C1 : B1 ⊕ C0]
	d1 := b0 ^ c1
	d0 := b1 ^ c0

	// Output: [D1 ⊕ X3 : D0 ⊕ X2]
	return fieldElement{d1 ^ x3, d0 ^ x2}
}

// mulx doubles x in GF(2^128).
func (x fieldElement) double() fieldElement {
	// h := x >> 127
	h := x.hi >> (127 - 64)

	// x <<= 1
	hi := x.hi<<1 | x.lo>>(64-1)
	lo := x.lo << 1

	// v ^= h ^ (h << 127) ^ (h << 126) ^ (h << 121)
	lo ^= h
	hi ^= h << (127 - 64) // h << 127
	hi ^= h << (126 - 64) // h << 126
	hi ^= h << (121 - 64) // h << 121

	return fieldElement{hi: hi, lo: lo}
}
