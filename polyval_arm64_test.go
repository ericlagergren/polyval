//go:build arm64

package polyval

import (
	"fmt"
	"testing"
)

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
