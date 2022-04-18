// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gcm

import (
	"encoding/binary"
)

// gcmFieldElement represents a value in GF(2¹²⁸). In order to reflect the GCM
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//   the coefficient of x⁰ can be obtained by v.low >> 63.
//   the coefficient of x⁶³ can be obtained by v.low & 1.
//   the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//   the coefficient of x¹²⁷ can be obtained by v.high & 1.
type gcmFieldElement struct {
	low, high uint64
}

func (z *gcmFieldElement) setBytes(p []byte) {
	z.low = binary.BigEndian.Uint64(p[:8])
	z.high = binary.BigEndian.Uint64(p[8:])
}

func (x gcmFieldElement) marshal() []byte {
	out := make([]byte, 16)
	binary.BigEndian.PutUint64(out, x.low)
	binary.BigEndian.PutUint64(out[8:], x.high)
	return out
}

// gcm represents a Galois Counter Mode with a specific key. See
// https://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
type gcm struct {
	y gcmFieldElement
	// productTable contains the first sixteen powers of the key, H.
	// However, they are in bit reversed order.
	productTable [16]gcmFieldElement
}

func New(key []byte) *gcm {
	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	var x gcmFieldElement
	x.setBytes(key)

	var g gcm
	g.productTable[reverseBits(1)] = x
	for i := 2; i < 16; i += 2 {
		g.productTable[reverseBits(i)] = gcmDouble(g.productTable[reverseBits(i/2)])
		g.productTable[reverseBits(i+1)] = gcmAdd(g.productTable[reverseBits(i)], x)
	}
	return &g
}

// reverseBits reverses the order of the bits of 4-bit number in i.
func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// gcmAdd adds two elements of GF(2¹²⁸) and returns the sum.
func gcmAdd(x, y gcmFieldElement) gcmFieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
}

func Mulx(s []byte) []byte {
	var x gcmFieldElement
	x.setBytes(s)
	return gcmDouble(x).marshal()
}

// gcmDouble returns the result of doubling an element of GF(2¹²⁸).
func gcmDouble(x gcmFieldElement) (double gcmFieldElement) {
	msbSet := x.high&1 == 1

	// Because of the bit-ordering, doubling is actually a right shift.
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	// If the most-significant bit was set before shifting then it,
	// conceptually, becomes a term of x^128. This is greater than the
	// irreducible polynomial so the result has to be reduced. The
	// irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
	// eliminate the term at x^128 which also means subtracting the other
	// four terms. In characteristic 2 fields, subtraction == addition ==
	// XOR.
	if msbSet {
		double.low ^= 0xe100000000000000
	}
	return
}

var gcmReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// mul sets y to y*H, where H is the GCM key.
func (g *gcm) mul(y gcmFieldElement) gcmFieldElement {
	var z gcmFieldElement

	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}

		// Multiplication works by multiplying z by 16 and adding in
		// one of the precomputed multiples of H.
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(gcmReductionTable[msw]) << 48

			// the values in |table| are ordered for
			// little-endian bit positions.
			t := g.productTable[word&0xf]

			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}
	return z
}

const (
	gcmBlockSize = 16
)

// UpdateBlocks extends y with more polynomial terms from blocks, based on
// Horner's rule. There must be a multiple of gcmBlockSize bytes in blocks.
func (g *gcm) UpdateBlocks(blocks []byte) {
	if len(blocks)%16 != 0 {
		panic("invalid block size")
	}
	for len(blocks) > 0 {
		g.y.low ^= binary.BigEndian.Uint64(blocks)
		g.y.high ^= binary.BigEndian.Uint64(blocks[8:])
		g.y = g.mul(g.y)
		blocks = blocks[gcmBlockSize:]
	}
}

func (g *gcm) Sum(b []byte) []byte {
	return g.y.marshal()
}
