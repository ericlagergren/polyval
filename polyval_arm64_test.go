//go:build arm64

package polyval

import (
	"testing"
)

func BenchmarkPolyvalNoSHA3_1(b *testing.B) {
	benchmarkPolyvalNoSHA3(b, 1)
}

func BenchmarkPolyvalNoSHA3_4(b *testing.B) {
	benchmarkPolyvalNoSHA3(b, 4)
}

func BenchmarkPolyvalNoSHA3_8(b *testing.B) {
	benchmarkPolyvalNoSHA3(b, 8)
}

func BenchmarkPolyvalNoSHA3_16(b *testing.B) {
	benchmarkPolyvalNoSHA3(b, 16)
}

func BenchmarkPolyvalNoSHA3_32(b *testing.B) {
	benchmarkPolyvalNoSHA3(b, 32)
}

func BenchmarkPolyvalNoSHA3_64(b *testing.B) {
	benchmarkPolyvalNoSHA3(b, 64)
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
