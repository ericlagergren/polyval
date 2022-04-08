package main

import (
	. "github.com/mmcloughlin/avo/build"
	// . "github.com/mmcloughlin/avo/gotypes"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run asm.go -out ../polyval_amd64.s -stubs ../stub_amd64.go -pkg polyval

var mask Mem

func main() {
	Package("github.com/ericlagergren/polyval")
	ConstraintExpr("gc,!purego")

	mask = GLOBL("polymask", RODATA|NOPTR)
	DATA(0, U64(0xc200000000000000))
	DATA(8, U64(0xc200000000000000))

	declarePolymul()
	declarePolymulBlocks()

	Generate()
}

// The following assembly is a literal translation of
// polymulGeneric and polyBlocksGeneric. See those functions
// for more information on the algorithms.
//
// For a slightly easier to read example using intrinsics
// see https://gist.github.com/ericlagergren/28f9178bff76fcc2a0c043f16656548d
// and the corresponding Compiler Explorer output https://godbolt.org/z/5W55a1vqa

// karatsuba1 performs the first half of Karatsuba multiplication
// of x and y.
//
// The results are written to H, L = x, and M.
//
//    t0 = (x.hi, x.lo)
//    t0 = (x.hi, x.lo) ^ (x.lo, x.hi)
//       = (x.hi^x.lo, x.lo^x.hi)
//
//    M = (y.hi, y.lo)
//    M = (y.hi, y.lo) ^ (y.lo, y.hi)
//      = (y.hi^y.lo, y.lo^y.hi)
//
//    M = x.hi^x.lo * y.hi^y.lo
//    H = y.hi*x.hi
//    L = y.lo*x.lo
//
func karatsuba1(x, y VecVirtual) (H, L, M VecVirtual) {
	Comment("Karatsuba 1")
	H = XMM()   // high
	L = x       // low
	M = XMM()   // mid
	t0 := XMM() // temp
	PSHUFD(U8(0xEE), x, t0)
	PXOR(x, t0)
	PSHUFD(U8(0xEE), y, M)
	PXOR(y, M)
	PCLMULQDQ(U8(0x00), t0, M)
	MOVOU(x, H)
	PCLMULQDQ(U8(0x11), y, H)
	PCLMULQDQ(U8(0x00), y, L)
	return H, L, M
}

// karatsuba2 performs the second half of Karatsuba
// multiplication using H, L, and M.
//
// The results are written to x01 = L and x23 = H.
//
// We need to finish the Karatsuba multiplication by applying
// H and L to M and M to H and L.
//
//    t1 = (l0, l1) // L
//    t1 = (l1, h0) // shuf(H, t1)
//
//    t2 = (h0, h1)
//
//    t2 = (h0, h1) ^ (l0, l1)
//       = (h0^l0, h1^l1)
//
//    t2 = (h0^l0, h1^l1) ^ (l1, h0)
//       = (h0^l0^l1, h1^l1^h0)
//
//    t2 = (h0^l0^l1, h1^l1^h0) ^ (m0, m1)
//       = (h0^l0^l1^m0, h1^l1^h0^m1)
//
//    x23 = (h1^l1^h0^m1, h1)
//    x01 = (l0, h0^l0^l1^m0)
//
func karatsuba2(H, L, M VecVirtual) (x01, x23 VecVirtual) {
	Comment("Karatsuba 2")
	t1 := XMM() // temp
	t2 := XMM() // temp
	MOVOU(L, t1)
	SHUFPS(U8(0x4E), H, t1)
	MOVOU(H, t2)
	PXOR(L, t2)
	PXOR(t1, t2)
	PXOR(M, t2)
	MOVHLPS(t2, H)    // x23
	PUNPCKLQDQ(t2, L) // x01
	return L, H
}

// reduce performs Montgomery reduction on x01 and x23 and writes
// the result to v.
//
// Perform the Montgomery reduction over the 256-bit X.
//    [A1:A0] = X0 • 0xc200000000000000
//    [B1:B0] = [X0 ⊕ A1 : X1 ⊕ A0]
//    [C1:C0] = B0 • 0xc200000000000000
//    [D1:D0] = [B0 ⊕ C1 : B1 ⊕ C0]
// Output: [D1 ⊕ X3 : D0 ⊕ X2]
func reduce(mask, v, x01, x23 VecVirtual) {
	Comment("Montgomery reduce")
	MOVOU(mask, v)
	PCLMULQDQ(U8(0x00), x01, v)  // (A1, A0) = X0 * poly
	PSHUFD(U8(0x4E), v, v)       // (A1, A0) = (A0, A1)
	PXOR(x01, v)                 // (B1, B0) = (X0^A1, X1^A0)
	XORPS(v, x23)                // (D1, D0) = (B1^X3, B0^X2)
	PCLMULQDQ(U8(0x11), mask, v) // (C1, C0) = B0 * poly
	PXOR(x23, v)                 // [D1^X3 : D0^X2]
}

// polymul set z = x*y.
//
// It clobbers x.
func polymul(mask, z, x, y VecVirtual) {
	H, L, M := karatsuba1(x, y)
	x01, x23 := karatsuba2(H, L, M)
	reduce(mask, z, x01, x23)
}

func loadMask() VecVirtual {
	m := XMM()
	MOVOU(mask, m)
	return m
}

func declarePolymul() {
	TEXT("polymulAsm", NOSPLIT, "func(acc, key *fieldElement)")
	Pragma("noescape")

	acc := Load(Param("acc"), GP64())
	key := Load(Param("key"), GP64())

	x, y := XMM(), XMM()
	MOVOU(Mem{Base: acc}, x)
	MOVOU(Mem{Base: key}, y)

	z := XMM()
	polymul(loadMask(), z, x, y)
	MOVOU(z, Mem{Base: acc})

	RET()
}

func declarePolymulBlocks() {
	TEXT("polymulBlocksAsm", NOSPLIT, "func(acc *fieldElement, pow *[8]fieldElement, input *byte, nblocks int)")
	Pragma("noescape")

	acc := Mem{Base: Load(Param("acc"), GP64())}
	pow := Mem{Base: Load(Param("pow"), GP64())}
	input := Mem{Base: Load(Param("input"), GP64())}
	nblocks := Load(Param("nblocks"), GP64())

	mask := loadMask()

	d := XMM()
	MOVOU(acc, d)

	nsingle := GP64()
	MOVQ(nblocks, nsingle)
	ANDQ(U8(7), nsingle)
	JZ(LabelRef("initWideLoop"))

	// Single loop handles any excess blocks if nblocks is not
	// a multiple of the stride.
	Label("initSingleLoop")
	key := XMM()
	MOVOU(pow.Offset(7*16), key)

	Label("singleLoop")
	msg := XMM()
	MOVOU(input, msg)
	PXOR(d, msg)
	polymul(mask, d, msg, key)

	ADDQ(U8(16), input.Base)
	SUBQ(U8(1), nsingle)
	JNZ(LabelRef("singleLoop"))

	// Wide loop handles full 8-block strides.
	Label("initWideLoop")
	nwide := GP64()
	MOVQ(nblocks, nwide)
	SHRQ(U8(3), nwide)
	JZ(LabelRef("done"))

	Label("wideLoop")
	{
		H, M, L := XMM(), XMM(), XMM()
		PXOR(H, H)
		PXOR(L, L)
		PXOR(M, M)
		for i := 7; i >= 0; i-- {
			Commentf("Block %d", i)
			msg, key := XMM(), XMM()
			MOVOU(input.Offset(i*16), msg)
			MOVOU(pow.Offset(i*16), key)
			if i == 0 {
				// Fold in accumulator
				PXOR(d, msg)
			}
			h, l, m := karatsuba1(msg, key)
			PXOR(h, H)
			PXOR(l, L)
			PXOR(m, M)
		}
		x01, x23 := karatsuba2(H, L, M)
		reduce(mask, d, x01, x23)

		ADDQ(U8(8*16), input.Base)
		SUBQ(U8(1), nwide)
		JNZ(LabelRef("wideLoop"))
	}

	Label("done")
	MOVOU(d, acc)

	RET()
}
