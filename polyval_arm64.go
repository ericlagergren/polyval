package polyval

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

var haveAsm = runtime.GOOS == "darwin" ||
	runtime.GOOS == "ios" ||
	cpu.ARM64.HasPMULL

//go:noescape
func polymul(acc, key *fieldElement, input *byte)
