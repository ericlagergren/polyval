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
	VEXT $8, H.B16, L.B16, tmp2.B16   \
	VEOR tmp2.B16, M.B16, M.B16       \
	VEOR L.B16, H.B16, tmp2.B16       \
	VEOR M.B16, tmp2.B16, tmp2.B16    \
	VEXT $8, H.B16, H.B16, H.B16      \
	VEXT $8, L.B16, L.B16, L.B16      \
	VEXT $8, tmp2.B16, L.B16, x01.B16 \
	VEXT $8, H.B16, tmp2.B16, x23.B16

#define KARATSUBA_2_SHA3() \
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
	VPMULL  x01.D1, poly.D1, a.Q1   \
	VEXT    $8, a.B16, a.B16, b.B16 \
	VEOR    x01.B16, b.B16, b.B16   \
	VPMULL2 b.D2, poly.D2, c.Q1     \
	VEOR    c.B16, b.B16, d.B16     \
	VEOR    x23.B16, d.B16, d.B16

#define REDUCE_SHA3() \
	VPMULL  x01.D1, poly.D1, a.Q1        \
	VEXT    $8, a.B16, a.B16, b.B16      \
	VEOR    x01.B16, b.B16, b.B16        \
	VPMULL2 b.D2, poly.D2, c.Q1          \
	VEOR3   c.B16, b.B16, x23.B16, d.B16

// func polymulAsm(acc, key *fieldElement)
TEXT ·polymulAsm(SB), NOSPLIT, $0-16
#define acc_ptr R0
#define key_ptr R1
#define have_sha3 R2

#define x V13
#define y V14

	MOVD acc+0(FP), acc_ptr
	MOVD key+8(FP), key_ptr

	VLD1 (acc_ptr), [x.B16]
	VLD1 (key_ptr), [y.B16]

	LOAD_POLY()
	KARATSUBA_1(x, y)

	MOVBU ·haveSHA3(SB), have_sha3
	CBNZ  have_sha3, reduce_sha3

reduce:
	KARATSUBA_2()
	REDUCE()
	B done

reduce_sha3:
	KARATSUBA_2_SHA3()
	REDUCE_SHA3()

done:
	VST1 [d.B16], (acc_ptr)

	RET

#undef acc_ptr
#undef key_ptr
#undef have_sha3
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

// func polymulBlocksAsmSHA3(acc *fieldElement, pow *[8]fieldElement, input *byte, nblocks int)
TEXT ·polymulBlocksAsmSHA3(SB), NOSPLIT, $0-32
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
	KARATSUBA_2_SHA3()
	REDUCE_SHA3()

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

	KARATSUBA_2_SHA3()
	REDUCE_SHA3()

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

// ctmulAsm is derived from Clang's assembly output for the
// corresponding C program for https://godbolt.org/z/Eo8oxqc3o

// func ctmulAsm(x, y uint64) (z1, z0 uint64)
TEXT ·ctmulAsm(SB), NOSPLIT, $0-32
	MOVD x+0(FP), R0
	MOVD y+8(FP), R1

	MOVD  $16912, R8
	MOVK  $(8456<<16), R8
	MOVK  $(4228<<32), R8
	MOVK  $(2114<<48), R8
	MOVD  $2114, R17
	MOVK  $(33825<<16), R17
	MOVK  $(16912<<32), R17
	MOVK  $(8456<<48), R17
	AND   R14, R17, R0
	AND   R15, R8, R1
	UMULH R6, R14, R15
	MOVD  $33825, R9
	MOVK  $(16912<<16), R9
	MOVK  $(8456<<32), R9
	MOVK  $(4228<<48), R9
	AND   R16, R9, R0
	AND   R10, R17, R1
	UMULH R7, R16, R10
	UMULH R19, R10, R14
	MOVD  $8456, R5
	MOVK  $(4228<<16), R5
	MOVK  $(2114<<32), R5
	MOVD  $0x8421000000000000, R5 // MOVK $(33825<<48), R5
	AND   R3, R5, R1
	UMULH R20, R16, R3
	MUL   R21, R14, R15
	MUL   R22, R16, R10
	AND   R13, R5, R0
	MOVD  $4228, R4
	MOVK  $(2114<<16), R4
	MOVK  $(33825<<32), R4
	MOVK  $(16912<<48), R4
	MUL   R23, R10, R14
	AND   R2, R4, R0
	AND   R11, R9, R1
	MUL   R24, R16, R3
	AND   R12, R8, R0
	AND   R0, R4, R1
	MUL   R1, R14, R0
	EOR   R1, R1, R24
	MUL   R24, R0, R16
	EOR   R23, R24, R23
	MUL   R24, R11, R14
	EOR   R22, R24, R22
	MUL   R24, R16, R11
	EOR   R21, R24, R21
	UMULH R24, R14, R0
	EOR   R20, R24, R20
	UMULH R24, R0, R16
	EOR   R19, R24, R19
	UMULH R24, R11, R14
	EOR   R7, R24, R7
	UMULH R24, R16, R11
	EOR   R6, R24, R6
	UMULH R24, R2, R3
	EOR   R6, R24, R6
	UMULH R24, R2, R15
	EOR   R7, R24, R7
	UMULH R24, R11, R2
	EOR   R19, R24, R19
	UMULH R24, R2, R10
	EOR   R20, R24, R20
	MUL   R24, R2, R3
	EOR   R21, R24, R21
	MUL   R24, R2, R15
	EOR   R22, R24, R22
	MUL   R24, R11, R2
	EOR   R23, R24, R23
	MUL   R24, R2, R10
	EOR   R1, R24, R1
	MUL   R24, R13, R11
	EOR   R1, R24, R1
	MUL   R24, R15, R13
	EOR   R23, R24, R23
	MUL   R24, R13, R3
	EOR   R22, R24, R22
	MUL   R24, R13, R0
	EOR   R21, R24, R21
	UMULH R24, R13, R11
	EOR   R20, R24, R20
	UMULH R24, R15, R13
	EOR   R19, R24, R19
	UMULH R24, R13, R3
	EOR   R7, R24, R7
	UMULH R24, R13, R0
	EOR   R6, R24, R6
	UMULH R24, R12, R10
	EOR   R6, R24, R6
	UMULH R24, R0, R12
	EOR   R7, R24, R7
	UMULH R24, R12, R3
	EOR   R19, R24, R19
	UMULH R24, R12, R15
	EOR   R20, R24, R20
	MUL   R24, R12, R10
	EOR   R21, R24, R21
	MUL   R24, R0, R12
	EOR   R22, R24, R22
	MUL   R24, R12, R3
	EOR   R23, R24, R23
	MUL   R24, R12, R15
	EOR   R1, R24, R1
	AND   R1, R5, R1
	MOVD  $8456, R5
	MOVK  $(4228<<16), R5
	MOVK  $(2114<<32), R5
	MOVK  $(1057<<48), R5
	AND   R5, R5, R19
	AND   R19, R4, R23
	AND   R22, R17, R22
	AND   R4, R4, R7
	AND   R17, R17, R6
	UMULH R6, R16, R15
	UMULH R7, R14, R3
	EOR   R6, R7, R6
	MUL   R15, R16, R15
	MUL   R14, R14, R3
	EOR   R14, R14, R15
	MUL   R15, R2, R0
	EOR   R14, R15, R14
	UMULH R15, R2, R0
	EOR   R15, R15, R6
	UMULH R16, R13, R10
	EOR   R15, R16, R15
	MUL   R10, R13, R10
	EOR   R10, R10, R14
	MUL   R13, R12, R11
	EOR   R10, R13, R10
	UMULH R11, R12, R11
	EOR   R11, R11, R15
	AND   R12, R9, R21
	AND   R9, R9, R11
	AND   R11, R8, R20
	AND   R8, R8, R10
	ORR   R10, R4, R17
	ORR   R10, R5, R10
	ORR   R10, R11, R10
	ORR   R11, R22, R12
	ORR   R11, R19, R11
	ORR   R11, R1, R11
	ORR   R0, R8, R11
	ORR   R1, R9, R10

	MOVD R1, z1+16(FP)
	MOVD R0, z0+24(FP)
	RET
