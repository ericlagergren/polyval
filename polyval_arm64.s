//go:build gc && !purego

#include "textflag.h"

// The following assembly is a literal translation of
// polymulGeneric and polymulBlocksGeneric. See those functions
// for more information on the algorithm.
//
// For a slightly easier to read example using intrinsics,
// see https://gist.github.com/ericlagergren/7a0af12f0d6f5e31ffffbe3e634c3944
// and the corresponding Compiler Explorer output https://godbolt.org/z/s7d3MfE1G
//
// See also Google's implementation
// https://github.com/google/hctr2/blob/2a80dc7f742127b1f68f02b310975ac7928ae25e/benchmark/src/aarch64/polyval-pmull_asm.S
// which includes support for multiple blocks.

#define H V0
#define L V1
#define M V2
#define x01 V3
#define x23 V4
#define tmp0 V5
#define tmp1 V6
#define tmp2 V7
#define poly V8
#define a V9
#define b V10
#define c V11
#define d V12

#define LOAD_POLY() VMOVQ $0xc200000000000000, $0xc200000000000000, poly

// KARATSUBA_1 performs the first half of Karatsuba
// multiplication of |x| and |y|.
//
// The results are written directly to |H|, |L|, and |M|.
//
//    tmp0 = {x.hi, y.lo}
//    tmp0 = {x.hi, y.lo} ^ {x.lo, x.hi}
//         = {x.hi^x.lo, y.lo^x.hi}
//
//    tmp1 = {y.hi, y.lo}
//    tmp1 = {y.hi, y.lo} ^ {y.lo, y.hi}
//         = {y.hi^y.lo, y.lo^y.hi}
//
//    L = x.lo*y.lo
//    M = y.hi^y.lo * x.hi^x.lo
//    H = x.hi*y.hi
//
#define KARATSUBA_1(x, y) \
	VEXT    $8, y.B16, x.B16, tmp0.B16 \
	VEOR    x.B16, tmp0.B16, tmp0.B16  \
	VEXT    $8, y.B16, y.B16, tmp1.B16 \
	VEOR    y.B16, tmp1.B16, tmp1.B16  \
	VPMULL  tmp1.D1, tmp0.D1, M.Q1     \
	VPMULL2 y.D2, x.D2, H.Q1           \
	VPMULL  y.D1, x.D1, L.Q1

// KARATSUBA_1_XOR performs the first half of Karatsuba
// multiplication of |x| and |y|.
//
// The results are XORed with |H|, |L|, and |M|.
//
// Clobbers |x|.
#define KARATSUBA_1_XOR(x, y) \
	VEXT    $8, y.B16, x.B16, tmp0.B16 \
	VEOR    x.B16, tmp0.B16, tmp0.B16  \
	VEXT    $8, y.B16, y.B16, tmp1.B16 \
	VEOR    y.B16, tmp1.B16, tmp1.B16  \
	VPMULL  tmp1.D1, tmp0.D1, tmp0.Q1  \
	VPMULL2 y.D2, x.D2, tmp1.Q1        \
	VPMULL  y.D1, x.D1, x.Q1           \
	VEOR    tmp0.B16, M.B16, M.B16     \
	VEOR    tmp1.B16, H.B16, H.B16     \
	VEOR    x.B16, L.B16, L.B16

// KARATSUBA_2 performs the second half of Karatsuba
// multiplication using |H|, |L|, and |M|.
//
// The results are written to |x01| and |x23|.
//
// We need to finish the Karatsuba multiplication by applying
// H and L to M and M to H and L.
//
//    tmp2 = {l1, h0}
//
//    M = {l1, h0} ^ {m0, m1}
//      = {l1^m0, h0^m1}
//
//    tmp2 = {l0, l1} ^ {h0, h1}
//         = {l0^h0, l1^h1}
//
//    tmp2 = {l0^h0, l1^h1} ^ {l1^m0, h0^m1}
//         = {l0^h0^l1^m0, l1^h1^h0^m1}
//
//    H = {h1, h0}
//    L = {l1, l0}
//
//           x0       x1
//    x01 = {l0, l0^h0^l1^m0}
//
//               x2       x3
//    x23 = {l1^h1^h0^m1, h1}
//
#define KARATSUBA_2() \
	VEXT  $8, H.B16, L.B16, tmp2.B16    \
	VEOR  tmp2.B16, M.B16, M.B16        \
	VEOR3 L.B16, H.B16, M.B16, tmp2.B16 \
	VEXT  $8, H.B16, H.B16, H.B16       \
	VEXT  $8, L.B16, L.B16, L.B16       \
	VEXT  $8, tmp2.B16, L.B16, x01.B16  \
	VEXT  $8, H.B16, tmp2.B16, x23.B16

// REDUCE performs Montgomery reduction on |x01| and |x23|,
//
// The result is written to |d|.
//
// Perform the Montgomery reduction over the 256-bit X.
//    [A1:A0] = X0 • 0xc200000000000000
//    [B1:B0] = [X0 ⊕ A1 : X1 ⊕ A0]
//    [C1:C0] = B0 • 0xc200000000000000
//    [D1:D0] = [B0 ⊕ C1 : B1 ⊕ C0]
// Output: [D1 ⊕ X3 : D0 ⊕ X2]
#define REDUCE() \
	VPMULL  x01.D1, poly.D1, a.Q1        \
	VEXT    $8, a.B16, a.B16, b.B16      \
	VEOR    x01.B16, b.B16, b.B16        \
	VPMULL2 b.D2, poly.D2, c.Q1          \
	VEOR3   c.B16, b.B16, x23.B16, d.B16

// func polymulAsm(acc, key *fieldElement)
TEXT ·polymulAsm(SB), NOSPLIT, $0-16
#define acc_ptr R0
#define key_ptr R1

#define x V13
#define y V14

	MOVD acc+0(FP), acc_ptr
	MOVD key+8(FP), key_ptr

	VLD1 (acc_ptr), [x.B16]
	VLD1 (key_ptr), [y.B16]

	LOAD_POLY()
	KARATSUBA_1(x, y)
	KARATSUBA_2()
	REDUCE()

	VST1 [d.B16], (acc_ptr)

	RET

#undef acc_ptr
#undef key_ptr
#undef x
#undef y

// func polymulBlocksAsm(acc *fieldElement, pow *[8]fieldElement, input *byte, nblocks int)
TEXT ·polymulBlocksAsm(SB), NOSPLIT, $0-32
#define acc_ptr R0
#define pow_ptr R1
#define input_ptr R2
#define remain R3
#define nwide R4
#define nsingle R5

#define m0 V16
#define m1 V17
#define m2 V18
#define m3 V19
#define m4 V20
#define m5 V21
#define m6 V22
#define m7 V23

#define h0 V24
#define h1 V25
#define h2 V26
#define h3 V27
#define h4 V28
#define h5 V29
#define h6 V30
#define h7 V31

	MOVD acc+0(FP), acc_ptr
	MOVD pow+8(FP), pow_ptr
	MOVD input+16(FP), input_ptr
	MOVD nblocks+24(FP), remain

	LOAD_POLY()
	VLD1 (acc_ptr), [d.B16]

	ANDS $7, remain, nsingle
	BEQ  initWideLoop

initSingleLoop:
	MOVD pow+8(FP), pow_ptr
	ADD  $128-16, pow_ptr
	VLD1 (pow_ptr), [h7.B16]

singleLoop:
	VLD1.P 16(input_ptr), [m0.B16]

	VEOR d.B16, m0.B16, m0.B16
	KARATSUBA_1(m0, h7)
	KARATSUBA_2()
	REDUCE()

	SUBS $1, nsingle
	BNE  singleLoop

initWideLoop:
	ASR $3, remain, nwide
	CBZ nwide, done

	MOVD   pow+8(FP), pow_ptr
	VLD1.P 64(pow_ptr), [h0.B16, h1.B16, h2.B16, h3.B16]
	VLD1.P 64(pow_ptr), [h4.B16, h5.B16, h6.B16, h7.B16]

wideLoop:
	VLD1.P 64(input_ptr), [m0.B16, m1.B16, m2.B16, m3.B16]
	VLD1.P 64(input_ptr), [m4.B16, m5.B16, m6.B16, m7.B16]

	VEOR H.B16, H.B16, H.B16
	VEOR L.B16, L.B16, L.B16
	VEOR M.B16, M.B16, M.B16

	KARATSUBA_1_XOR(m7, h7)
	KARATSUBA_1_XOR(m6, h6)
	KARATSUBA_1_XOR(m5, h5)
	KARATSUBA_1_XOR(m4, h4)
	KARATSUBA_1_XOR(m3, h3)
	KARATSUBA_1_XOR(m2, h2)
	KARATSUBA_1_XOR(m1, h1)
	VEOR d.B16, m0.B16, m0.B16 // Fold in accumulator
	KARATSUBA_1_XOR(m0, h0)

	KARATSUBA_2()
	REDUCE()

	SUBS $1, nwide
	BNE  wideLoop

done:
	VST1 [d.B16], (acc_ptr)

	RET

#undef acc_ptr
#undef pow_ptr
#undef input_ptr
#undef remain
#undef nwide
#undef nsingle

#undef m0
#undef m1
#undef m2
#undef m3
#undef m4
#undef m5
#undef m6
#undef m7

#undef h0
#undef h1
#undef h2
#undef h3
#undef h4
#undef h5
#undef h6
#undef h7
