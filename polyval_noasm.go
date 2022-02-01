//go:build !gc || noasm

package polyval

func polymul(acc, key *fieldElement) {
	polymulGeneric(acc, key)
}

func polymulBlocks(acc, key *fieldElement, blocks []byte) {
	polymulBlocksGeneric(acc, key, blocks)
}
