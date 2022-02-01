#include "textflag.h"

// func polymul(acc, key *fieldElement, input *byte)
TEXT ·polymul(SB), NOSPLIT, $0-24
#define acc_ptr R0
#define key_ptr R1
#define input_ptr R2

#define X V0
#define Y V1
#define V V2

#define H V3
#define L V4
#define M V5

#define x01 V6
#define x23 V7

#define a V8
#define b V9
#define c V10
#define d V11

#define poly V12

#define tmp0 V13
#define tmp1 V14
#define tmp2 V15

	MOVD acc+0(FP), acc_ptr
	MOVD key+8(FP), key_ptr
	MOVD input+16(FP), input_ptr

	VLD1 (acc_ptr), [X.B16]
	VLD1 (key_ptr), [Y.B16]
	VLD1 (input_ptr), [V.B16]

	// The following assembly is a literal translation of
	// polymulGeneric. See that function for more information on
	// the algorithm.
	//
	// For a slightly easier to read example using intrinsics,
	// see https://gist.github.com/ericlagergren/7a0af12f0d6f5e31ffffbe3e634c3944
	// and the corresponding Compiler Explorer output https://godbolt.org/z/s7d3MfE1G
	//
	// See also Google's implementation
	// https://github.com/google/hctr2/blob/2a80dc7f742127b1f68f02b310975ac7928ae25e/benchmark/src/aarch64/polyval-pmull_asm.S
	// which includes support for multiple blocks.

	VEOR V.B16, X.B16, X.B16

	// Perform the initial half of Karatsuba multiplication.
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
	VEXT    $8, Y.B16, X.B16, tmp0.B16
	VEOR    X.B16, tmp0.B16, tmp0.B16
	VEXT    $8, Y.B16, Y.B16, tmp1.B16
	VEOR    Y.B16, tmp1.B16, tmp1.B16
	VPMULL  tmp1.D1, tmp0.D1, M.Q1
	VPMULL2 Y.D2, X.D2, H.Q1
	VPMULL  Y.D1, X.D1, L.Q1

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
	VEXT  $8, H.B16, L.B16, tmp2.B16
	VEOR  tmp2.B16, M.B16, M.B16
	VEOR3 L.B16, H.B16, M.B16, tmp2.B16
	VEXT  $8, H.B16, H.B16, H.B16
	VEXT  $8, L.B16, L.B16, L.B16
	VEXT  $8, tmp2.B16, L.B16, x01.B16
	VEXT  $8, H.B16, tmp2.B16, x23.B16

	// Perform the Montgomery reduction over the 256-bit X.
	//    [A1:A0] = X0 • 0xc200000000000000
	//    [B1:B0] = [X0 ⊕ A1 : X1 ⊕ A0]
	//    [C1:C0] = B0 • 0xc200000000000000
	//    [D1:D0] = [B0 ⊕ C1 : B1 ⊕ C0]
	// Output: [D1 ⊕ X3 : D0 ⊕ X2]
	VMOVQ   $0xc200000000000000, $0xc200000000000000, poly
	VPMULL  x01.D1, poly.D1, a.Q1
	VEXT    $8, a.B16, a.B16, b.B16
	VEOR    x01.B16, b.B16, b.B16
	VPMULL2 b.D2, poly.D2, c.Q1
	VEOR3   c.B16, b.B16, x23.B16, d.B16
	VST1    [d.B16], (acc_ptr)

	RET
