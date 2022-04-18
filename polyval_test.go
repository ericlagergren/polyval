package polyval

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// TestCtmulCommutative tests that ctmul is commutative,
// a required property for multiplication.
func TestCtmulCommutative(t *testing.T) {
	runTests(t, testCtmulCommutative)
}

func testCtmulCommutative(t *testing.T) {
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
	runTests(t, testPolyvalRFCVectors)
}

func testPolyvalRFCVectors(t *testing.T) {
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
		if got := Sum(tc.H, blocks); !bytes.Equal(want, got[:]) {
			t.Fatalf("#%d: expected %x, got %x", i, want, got[:])
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
	runTests(t, testMultiBlockUpdate)
}

func testMultiBlockUpdate(t *testing.T) {
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
	runTests(t, testPolyvalVectors)
}

func testPolyvalVectors(t *testing.T) {
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
		p.Update(blocks)
		polymulBlocksGeneric(&g.y, &g.pow, blocks)

		want := unhex(v.Hash)
		if got := p.Sum(nil); !bytes.Equal(want, got) {
			t.Fatalf("#%d: (%s): expected %x, got %x",
				i, v.Description, want, got)
		}
		if got := g.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("#%d: (%s): expected %x, got %x",
				i, v.Description, want, got)
		}
		if got := Sum(key, blocks); !bytes.Equal(want, got[:]) {
			t.Fatalf("#%d: (%s): expected %x, got %x",
				i, v.Description, want, got)
		}
	}
}

// TestZeroKey tests that New rejects zero keys.
func TestZeroKey(t *testing.T) {
	runTests(t, testZeroKey)
}

func testZeroKey(t *testing.T) {
	for _, tc := range []struct {
		key []byte
		ok  bool
	}{
		{key: make([]byte, 16), ok: false},
		{key: unhex("9871b36289fee421dbfdba32716e774c"), ok: true},
	} {
		_, err := New(tc.key)
		if (err == nil) != tc.ok {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

// TestMarshal tests Polyval's MarshalBinary and UnmarshalBinary
// methods.
func TestMarshal(t *testing.T) {
	runTests(t, testMarshal)
}

func testMarshal(t *testing.T) {
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

var (
	byteSink  []byte
	ctmulSink uint64
)

var benchBlocks = []int{
	1,   // 16
	4,   // 64
	8,   // 128
	16,  // 256
	32,  // 512
	64,  // 2048
	128, // 4096
	512, // 8192
}

func BenchmarkPolyval(b *testing.B) {
	for _, n := range benchBlocks {
		b.Run(fmt.Sprintf("%d", n*16), func(b *testing.B) {
			benchmarkPolyval(b, n)
		})
	}
}

func benchmarkPolyval(b *testing.B, nblocks int) {
	b.SetBytes(int64(nblocks) * 16)
	p, _ := New(unhex("01000000000000000000000000000000"))
	x := make([]byte, nblocks*p.BlockSize())
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p.Update(x)
	}
	byteSink = p.Sum(nil)
}

func BenchmarkPolyvalGeneric(b *testing.B) {
	for _, n := range benchBlocks {
		b.Run(fmt.Sprintf("%d", n*16), func(b *testing.B) {
			benchmarkPolyvalGeneric(b, n)
		})
	}
}

func benchmarkPolyvalGeneric(b *testing.B, nblocks int) {
	p, _ := New(unhex("01000000000000000000000000000000"))
	x := make([]byte, nblocks*p.BlockSize())
	b.SetBytes(int64(len(x)))
	b.ResetTimer()

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
