//go:build gc && !purego

package polyval

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

var haveAsm = runtime.GOOS == "darwin" ||
	runtime.GOOS == "ios" ||
	cpu.ARM64.HasPMULL

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

//go:noescape
func polymulAsm(acc, key *fieldElement)

//go:noescape
func polymulBlocksAsm(acc *fieldElement, pow *[8]fieldElement, input *byte, nblocks int)
