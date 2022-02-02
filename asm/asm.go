package main

import (
	. "github.com/mmcloughlin/avo/build"
	//. "github.com/mmcloughlin/avo/gotypes"
	. "github.com/mmcloughlin/avo/operand"
	//. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run asm.go -out ../polyval_amd64.s -stubs ../stub_amd64.go -pkg polyval

func main() {
	Package("github.com/ericlagergren/polyval")
	ConstraintExpr("gc,!purego")

	declareCtmul()

	Generate()
}

func declareCtmul() {
	TEXT("ctmulAsm", NOSPLIT, "func(z *fieldElement, x, y uint64)")
	Pragma("noescape")

	z := Load(Param("z"), GP64())
	x := Load(Param("x"), XMM())
	y := Load(Param("y"), XMM())
	PCLMULQDQ(U8(0x00), x, y)
	MOVOU(y, Mem{Base: z})

	RET()
}
