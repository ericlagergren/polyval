//go:build !(amd64 || arm64) || !gc || purego

package polyval

import "testing"

func runTests(t *testing.T, fn func(t *testing.T)) {
	t.Run("generic", fn)
}
