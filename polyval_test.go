package polyval

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/exp/rand"
)

func unhex(s string) []byte {
	p, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return p
}

func elem(s string) fieldElement {
	var z fieldElement
	z.setBytes(unhex(s))
	return z
}

// TestCtmulCommutative tests that ctmul is commutative,
// a required property for multiplication.
func TestCtmulCommutative(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewSource(seed))
	for i := 0; i < 1e6; i++ {
		x, y := rng.Uint64(), rng.Uint64()
		xy1, xy0 := ctmul(x, y)
		yx1, yx0 := ctmul(y, x)
		if xy1 != yx1 || xy0 != yx0 {
			t.Fatalf("%#0.16x*%#0.16x: (%#0.16x, %#0.16x) != (%#0.16x, %#0.16x)",
				x, y, xy1, xy0, yx1, yx0)
		}
	}
}

// TestPolyvalRFCVectors tests polyval using test vectors from
// RFC 8452.
func TestPolyvalRFCVectors(t *testing.T) {
	for i, tc := range []struct {
		H []byte
		X [][]byte
		r []byte
	}{
		// POLYVAL(H, X_1)
		{
			H: unhex("25629347589242761d31f826ba4b757b"),
			X: [][]byte{
				unhex("4f4f95668c83dfb6401762bb2d01a262"),
			},
			r: unhex("cedac64537ff50989c16011551086d77"),
		},
		// POLYVAL(H, X_1, X_2)
		{
			H: unhex("25629347589242761d31f826ba4b757b"),
			X: [][]byte{
				unhex("4f4f95668c83dfb6401762bb2d01a262"),
				unhex("d1a24ddd2721d006bbe45f20d3c9f362"),
			},
			r: unhex("f7a3b47b846119fae5b7866cf5e5b77e"),
		},
	} {
		blocks := make([]byte, 0, 16*len(tc.X))

		g, _ := New(tc.H) // generic
		p, _ := New(tc.H) // specialized
		for _, x := range tc.X {
			p.Update(x)
			polymulBlocksGeneric(&g.y, &g.pow, x)

			blocks = append(blocks, x...)
		}
		want := tc.r

		if got := p.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("#%d: expected %x, got %x", i, want, got)
		}
		if got := g.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("#%d: expected %x, got %x", i, want, got)
		}

		p.Reset()
		p.Update(blocks)
		if got := p.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("#%d: expected %x, got %x", i, want, got)
		}

		g.Reset()
		polymulBlocksGeneric(&g.y, &g.pow, blocks)
		if got := g.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("#%d: expected %x, got %x", i, want, got)
		}
	}
}

// TestMultiBlockUpdate is a quick test to check that single vs
// multi-block Update calls are equivalent.
func TestMultiBlockUpdate(t *testing.T) {
	key := make([]byte, 16)
	key[0] = 1
	w, _ := New(key)
	s, _ := New(key)

	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewSource(seed))
	buf := make([]byte, 224*67)
	rng.Read(buf)

	var dgw, dgs []byte
	for i := 16; i < len(buf); i += 16 {
		w.Update(buf[:i])
		for b := buf; len(b) > 0; b = b[16:] {
			s.Update(b[:16])
		}
		w.Sum(dgw[:0])
		s.Sum(dgs[:0])
		if !bytes.Equal(dgw, dgs) {
			t.Fatalf("mismatch: %x vs %x", dgw, dgs)
		}
	}
}

// TestPolyvalVectors tests polyval using the Google-provided
// test vectors.
//
// See https://github.com/google/hctr2/blob/2a80dc7f742127b1f68f02b310975ac7928ae25e/test_vectors/ours/Polyval/Polyval.json
func TestPolyvalVectors(t *testing.T) {
	type vector struct {
		Cipher struct {
			Cipher      string `json:"cipher"`
			BlockCipher struct {
				Cipher  string `json:"cipher"`
				Lengths struct {
					Block int `json:"block"`
					Key   int `json:"key"`
					Nonce int `json:"nonce"`
				} `json:"lengths"`
			} `json:"block_cipher"`
		} `json:"cipher"`
		Description string `json:"description"`
		Input       struct {
			Key     string `json:"key_hex"`
			Tweak   string `json:"tweak_hex"`
			Message string `json:"message_hex"`
			Nonce   string `json:"nonce_hex"`
		} `json:"input"`
		Plaintext  string `json:"plaintext_hex"`
		Ciphertext string `json:"ciphertext_hex"`
		Hash       string `json:"hash_hex"`
	}

	var vecs []vector
	buf, err := os.ReadFile(filepath.Join("testdata", "polyval.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(buf, &vecs)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range vecs {
		key := unhex(v.Input.Key)
		g, _ := New(key) // generic
		p, _ := New(key) // specialized

		blocks := unhex(v.Input.Message)
		if len(blocks) > 0 {
			p.Update(blocks)
			polymulBlocksGeneric(&g.y, &g.pow, blocks)
		}

		want := unhex(v.Hash)
		if got := p.Sum(nil); !bytes.Equal(want, got) {
			t.Fatalf("#%d: (%s): expected %x, got %x",
				i, v.Description, want, got)
		}
		if got := g.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("#%d: (%s): expected %x, got %x",
				i, v.Description, want, got)
		}
	}
}

// TestMarshal tests Polyval's MarshalBinary and UnmarshalBinary
// methods.
func TestMarshal(t *testing.T) {
	key := make([]byte, 16)
	key[0] = 1
	h, _ := New(key)
	blocks := make([]byte, 224)
	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewSource(seed))
	for i := 0; i < 5000; i++ {
		rng.Read(blocks)

		// Save the current digest and state.
		prevSum := h.Sum(nil)
		prev, _ := h.MarshalBinary()

		// Update the state and save the digest.
		h.Update(blocks)
		curSum := h.Sum(nil)

		// Read back the first state and check that we get the
		// same results.
		var h2 Polyval
		h2.UnmarshalBinary(prev)
		if got := h2.Sum(nil); !bytes.Equal(got, prevSum) {
			t.Fatalf("#%d: exepected %x, got %x", i, prevSum, got)
		}
		h2.Update(blocks)
		if got := h2.Sum(nil); !bytes.Equal(got, curSum) {
			t.Fatalf("#%d: exepected %x, got %x", i, curSum, got)
		}
	}
}

// TestDoubleRFCVectors tests double over the set of vectors from
// RFC 8452.
//
// See https://datatracker.ietf.org/doc/html/rfc8452#appendix-A
func TestDoubleRFCVectors(t *testing.T) {
	for i, tc := range []struct {
		input  fieldElement
		output fieldElement
	}{
		{
			input:  elem("01000000000000000000000000000000"),
			output: elem("02000000000000000000000000000000"),
		},
		{
			input:  elem("9c98c04df9387ded828175a92ba652d8"),
			output: elem("3931819bf271fada0503eb52574ca572"),
		},
	} {
		want := tc.output
		if got := tc.input.double(); got != want {
			t.Fatalf("#%d: expected %#x, got %#x", i, want, got)
		}
	}
}

// TestDoubleRustVectors tests double over the set of vectors
// from RustCrypto.
//
// See https://github.com/RustCrypto/universal-hashes/blob/5361f44a1162bd0d84e6560b6e30c7cb445e683f/polyval/src/double.rs#L58
func TestDoubleRustVectors(t *testing.T) {
	r := elem("01000000000000000000000000000000")

	for i, v := range []fieldElement{
		elem("02000000000000000000000000000000"),
		elem("04000000000000000000000000000000"),
		elem("08000000000000000000000000000000"),
		elem("10000000000000000000000000000000"),
		elem("20000000000000000000000000000000"),
		elem("40000000000000000000000000000000"),
		elem("80000000000000000000000000000000"),
		elem("00010000000000000000000000000000"),
		elem("00020000000000000000000000000000"),
		elem("00040000000000000000000000000000"),
		elem("00080000000000000000000000000000"),
		elem("00100000000000000000000000000000"),
		elem("00200000000000000000000000000000"),
		elem("00400000000000000000000000000000"),
		elem("00800000000000000000000000000000"),
		elem("00000100000000000000000000000000"),
		elem("00000200000000000000000000000000"),
		elem("00000400000000000000000000000000"),
		elem("00000800000000000000000000000000"),
		elem("00001000000000000000000000000000"),
		elem("00002000000000000000000000000000"),
		elem("00004000000000000000000000000000"),
		elem("00008000000000000000000000000000"),
		elem("00000001000000000000000000000000"),
		elem("00000002000000000000000000000000"),
		elem("00000004000000000000000000000000"),
		elem("00000008000000000000000000000000"),
		elem("00000010000000000000000000000000"),
		elem("00000020000000000000000000000000"),
		elem("00000040000000000000000000000000"),
		elem("00000080000000000000000000000000"),
		elem("00000000010000000000000000000000"),
		elem("00000000020000000000000000000000"),
		elem("00000000040000000000000000000000"),
		elem("00000000080000000000000000000000"),
		elem("00000000100000000000000000000000"),
		elem("00000000200000000000000000000000"),
		elem("00000000400000000000000000000000"),
		elem("00000000800000000000000000000000"),
		elem("00000000000100000000000000000000"),
		elem("00000000000200000000000000000000"),
		elem("00000000000400000000000000000000"),
		elem("00000000000800000000000000000000"),
		elem("00000000001000000000000000000000"),
		elem("00000000002000000000000000000000"),
		elem("00000000004000000000000000000000"),
		elem("00000000008000000000000000000000"),
		elem("00000000000001000000000000000000"),
		elem("00000000000002000000000000000000"),
		elem("00000000000004000000000000000000"),
		elem("00000000000008000000000000000000"),
		elem("00000000000010000000000000000000"),
		elem("00000000000020000000000000000000"),
		elem("00000000000040000000000000000000"),
		elem("00000000000080000000000000000000"),
		elem("00000000000000010000000000000000"),
		elem("00000000000000020000000000000000"),
		elem("00000000000000040000000000000000"),
		elem("00000000000000080000000000000000"),
		elem("00000000000000100000000000000000"),
		elem("00000000000000200000000000000000"),
		elem("00000000000000400000000000000000"),
		elem("00000000000000800000000000000000"),
		elem("00000000000000000100000000000000"),
		elem("00000000000000000200000000000000"),
		elem("00000000000000000400000000000000"),
		elem("00000000000000000800000000000000"),
		elem("00000000000000001000000000000000"),
		elem("00000000000000002000000000000000"),
		elem("00000000000000004000000000000000"),
		elem("00000000000000008000000000000000"),
		elem("00000000000000000001000000000000"),
		elem("00000000000000000002000000000000"),
		elem("00000000000000000004000000000000"),
		elem("00000000000000000008000000000000"),
		elem("00000000000000000010000000000000"),
		elem("00000000000000000020000000000000"),
		elem("00000000000000000040000000000000"),
		elem("00000000000000000080000000000000"),
		elem("00000000000000000000010000000000"),
		elem("00000000000000000000020000000000"),
		elem("00000000000000000000040000000000"),
		elem("00000000000000000000080000000000"),
		elem("00000000000000000000100000000000"),
		elem("00000000000000000000200000000000"),
		elem("00000000000000000000400000000000"),
		elem("00000000000000000000800000000000"),
		elem("00000000000000000000000100000000"),
		elem("00000000000000000000000200000000"),
		elem("00000000000000000000000400000000"),
		elem("00000000000000000000000800000000"),
		elem("00000000000000000000001000000000"),
		elem("00000000000000000000002000000000"),
		elem("00000000000000000000004000000000"),
		elem("00000000000000000000008000000000"),
		elem("00000000000000000000000001000000"),
		elem("00000000000000000000000002000000"),
		elem("00000000000000000000000004000000"),
		elem("00000000000000000000000008000000"),
		elem("00000000000000000000000010000000"),
		elem("00000000000000000000000020000000"),
		elem("00000000000000000000000040000000"),
		elem("00000000000000000000000080000000"),
		elem("00000000000000000000000000010000"),
		elem("00000000000000000000000000020000"),
		elem("00000000000000000000000000040000"),
		elem("00000000000000000000000000080000"),
		elem("00000000000000000000000000100000"),
		elem("00000000000000000000000000200000"),
		elem("00000000000000000000000000400000"),
		elem("00000000000000000000000000800000"),
		elem("00000000000000000000000000000100"),
		elem("00000000000000000000000000000200"),
		elem("00000000000000000000000000000400"),
		elem("00000000000000000000000000000800"),
		elem("00000000000000000000000000001000"),
		elem("00000000000000000000000000002000"),
		elem("00000000000000000000000000004000"),
		elem("00000000000000000000000000008000"),
		elem("00000000000000000000000000000001"),
		elem("00000000000000000000000000000002"),
		elem("00000000000000000000000000000004"),
		elem("00000000000000000000000000000008"),
		elem("00000000000000000000000000000010"),
		elem("00000000000000000000000000000020"),
		elem("00000000000000000000000000000040"),
		elem("00000000000000000000000000000080"),
		elem("010000000000000000000000000000c2"),
	} {
		want := v
		got := r.double()
		if got != want {
			t.Fatalf("#%d: expected %#x, got %#x", i, want, got)
		}
		r = got
	}
}

var (
	byteSink  []byte
	elemSink  fieldElement
	ctmulSink uint64
)

func BenchmarkDouble(b *testing.B) {
	x := fieldElement{
		hi: rand.Uint64(),
		lo: rand.Uint64(),
	}
	for i := 0; i < b.N; i++ {
		x = x.double()
	}
	elemSink = x
}

func BenchmarkPolyval_1(b *testing.B) {
	benchmarkPolyval(b, 1)
}

func BenchmarkPolyval_4(b *testing.B) {
	benchmarkPolyval(b, 4)
}

func BenchmarkPolyval_8(b *testing.B) {
	benchmarkPolyval(b, 8)
}

func BenchmarkPolyval_16(b *testing.B) {
	benchmarkPolyval(b, 16)
}

func benchmarkPolyval(b *testing.B, nblocks int) {
	b.SetBytes(int64(nblocks) * 16)
	p, _ := New(unhex("01000000000000000000000000000000"))
	x := make([]byte, nblocks*p.BlockSize())
	for i := 0; i < b.N; i++ {
		p.Update(x)
	}
	byteSink = p.Sum(nil)
}

func BenchmarkPolyvalGeneric_1(b *testing.B) {
	benchmarkPolyvalGeneric(b, 1)
}

func BenchmarkPolyvalGeneric_4(b *testing.B) {
	benchmarkPolyvalGeneric(b, 4)
}

func BenchmarkPolyvalGeneric_8(b *testing.B) {
	benchmarkPolyvalGeneric(b, 8)
}

func BenchmarkPolyvalGeneric_16(b *testing.B) {
	benchmarkPolyvalGeneric(b, 16)
}

func benchmarkPolyvalGeneric(b *testing.B, nblocks int) {
	p, _ := New(unhex("01000000000000000000000000000000"))
	x := make([]byte, nblocks*p.BlockSize())
	b.SetBytes(int64(len(x)))
	for i := 0; i < b.N; i++ {
		polymulBlocksGeneric(&p.y, &p.pow, x)
	}
	byteSink = p.Sum(nil)
}

func BenchmarkCtmul(b *testing.B) {
	z1 := rand.Uint64()
	z0 := rand.Uint64()
	for i := 0; i < b.N; i++ {
		z1, z0 = ctmul(z1, z0)
	}
	ctmulSink = z1 ^ z0
}
