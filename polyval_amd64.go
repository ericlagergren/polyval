//go:build gc && !purego

package polyval

import (
	"golang.org/x/sys/cpu"
)

var haveAsm = cpu.X86.HasPCLMULQDQ

func polymul(acc, key *fieldElement) {
	if haveAsm {
		polymulAsm(acc, key)
	} else {
		polymulGeneric(acc, key)
	}
}

func polymulBlocks(acc *fieldElement, pow *[8]fieldElement, blocks []byte) {
	if haveAsm {
		polymulBlocksAsm(acc, pow, &blocks[0], len(blocks)/16)
	} else {
		polymulBlocksGeneric(acc, pow, blocks)
	}
}

func ctmul(x, y uint64) (z1, z0 uint64) {
	return ctmulGeneric(x, y)
}
