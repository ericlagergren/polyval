//go:build arm64 && gc && !purego

package polyval

import (
	"fmt"
	"testing"
)

func disableAsm(t *testing.T) {
	old := haveAsm
	t.Cleanup(func() {
		haveAsm = old
	})
	haveAsm = false
}

func disableSHA3(t *testing.T) {
	old := haveSHA3
	t.Cleanup(func() {
		haveSHA3 = old
	})
	haveSHA3 = false
}

func runTests(t *testing.T, fn func(t *testing.T)) {
	if haveAsm {
		t.Run("assembly", fn)
		if haveSHA3 {
			t.Run("assemblyNoSHA3", func(t *testing.T) {
				disableSHA3(t)
				fn(t)
			})
		}
	}
	t.Run("generic", func(t *testing.T) {
		disableAsm(t)
		fn(t)
	})
}

func BenchmarkPolyvalNoSHA3(b *testing.B) {
	for _, n := range benchBlocks {
		b.Run(fmt.Sprintf("%d", n*16), func(b *testing.B) {
			benchmarkPolyvalNoSHA3(b, n)
		})
	}
}

func benchmarkPolyvalNoSHA3(b *testing.B, nblocks int) {
	if !haveSHA3 {
		b.Skip("CPU does not have SHA-3 extensions")
	}
	haveSHA3 = false
	b.Cleanup(func() {
		haveSHA3 = true
	})
	benchmarkPolyval(b, nblocks)
}
