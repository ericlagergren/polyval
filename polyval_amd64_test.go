//go:build amd64 && gc && !purego

package polyval

import (
	"testing"
)

func disableAsm(t *testing.T) {
	old := haveAsm
	t.Cleanup(func() {
		haveAsm = old
	})
	haveAsm = false
}

func runTests(t *testing.T, fn func(t *testing.T)) {
	if haveAsm {
		t.Run("assembly", fn)
	}
	t.Run("generic", func(t *testing.T) {
		disableAsm(t)
		fn(t)
	})
}
