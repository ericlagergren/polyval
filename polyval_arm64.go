//go:build gc && !purego

package polyval

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

var (
	haveAsm  = runtime.GOOS == "darwin" || cpu.ARM64.HasPMULL
	haveSHA3 = runtime.GOOS == "darwin" || cpu.ARM64.HasSHA3
)

func polymul(acc, key *fieldElement) {
	if haveAsm {
		polymulAsm(acc, key)
	} else {
		polymulGeneric(acc, key)
	}
}

func polymulBlocks(acc *fieldElement, pow *[8]fieldElement, blocks []byte) {
	if haveAsm {
		if haveSHA3 {
			polymulBlocksAsmSHA3(acc, pow, &blocks[0], len(blocks)/16)
		} else {
			polymulBlocksAsm(acc, pow, &blocks[0], len(blocks)/16)
		}
	} else {
		polymulBlocksGeneric(acc, pow, blocks)
	}
}

//go:noescape
func polymulAsm(acc, key *fieldElement)

//go:noescape
func polymulBlocksAsm(acc *fieldElement, pow *[8]fieldElement, input *byte, nblocks int)

//go:noescape
func polymulBlocksAsmSHA3(acc *fieldElement, pow *[8]fieldElement, input *byte, nblocks int)
