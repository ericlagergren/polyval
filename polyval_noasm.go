//go:build !(amd64 || arm64) || !gc || purego

package polyval

func polymul(acc, key *fieldElement) {
	polymulGeneric(acc, key)
}

func polymulBlocks(acc *fieldElement, pow *[8]fieldElement, blocks []byte) {
	polymulBlocksGeneric(acc, pow, blocks)
}

func ctmul(x, y uint64) (z1, z0 uint64) {
	return ctmulGeneric(x, y)
}
