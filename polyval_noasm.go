//go:build !(amd64 || arm64) || !gc || purego

package polyval

func polymul(acc, key *fieldElement) {
	polymulGeneric(acc, key)
}

func polymulBlocks(acc *fieldElement, pow *[8]fieldElement, blocks []byte) {
	polymulBlocksGeneric(acc, pow, blocks)
}
