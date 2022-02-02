package polyval

import (
	"golang.org/x/sys/cpu"
)

var haveAsm = cpu.X86.HasPCLMULQDQ

func polymul(acc, key *fieldElement) {
	polymulGeneric(acc, key)
}

func polymulBlocks(acc *fieldElement, pow *[8]fieldElement, blocks []byte) {
	polymulBlocksGeneric(acc, pow, blocks)
}

func ctmul(x, y uint64) (z1, z0 uint64) {
	if haveAsm {
		var z fieldElement
		ctmulAsm(&z, x, y)
		return z.hi, z.lo
	}
	return ctmulGeneric(x, y)
}
