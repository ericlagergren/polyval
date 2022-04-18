package polyval

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"testing"
	"time"

	tink "github.com/google/tink/go/aead/subtle"
	"golang.org/x/exp/rand"

	"github.com/ericlagergren/polyval/internal/gcm"
)

// TestFuzzTink runs fuzz tests against Google Tink's POLYVAL
// implementation.
func TestFuzzTink(t *testing.T) {
	runTests(t, testTink)
}

func testTink(t *testing.T) {
	d := 2 * time.Second
	if testing.Short() {
		d = 10 * time.Millisecond
	}
	timer := time.NewTimer(d)

	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewSource(seed))

	key := make([]byte, 16)
	const (
		N = 50
	)
	blocks := make([]byte, 16*N)
	for i := 0; ; i++ {
		select {
		case <-timer.C:
			t.Logf("iters: %d", i)
			return
		default:
		}

		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		blocks := blocks[:(rng.Intn(N-1)+1)*16]
		if _, err := rand.Read(blocks); err != nil {
			t.Fatal(err)
		}

		want, err := tink.NewPolyval(key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := New(key)
		if err != nil {
			t.Fatal(err)
		}

		want.Update(blocks)
		got.Update(blocks)

		wantHash := want.Finish()
		gotHash := got.Sum(nil)
		if !bytes.Equal(wantHash[:], gotHash) {
			t.Fatalf("expected %x, got %x", wantHash, gotHash)
		}
	}
}

// TestFuzzGCM runs fuzz tests against the GCM code from
// crypto/cipher.
//
// It checks that
//
//     GHASH(H, X_1, ..., X_n) =
//         ByteReverse(POLYVAL(mulX_POLYVAL(ByteReverse(H)),
//             ByteReverse(X_1), ..., ByteReverse(X_n)))
//
// and
//
//     POLYVAL(H, X_1, ..., X_n) =
//         ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
//             ByteReverse(X_1), ..., ByteReverse(X_n)))
//
func TestFuzzGCM(t *testing.T) {
	runTests(t, testGCM)
}

func testGCM(t *testing.T) {
	d := 2 * time.Second
	if testing.Short() {
		d = 10 * time.Millisecond
	}
	timer := time.NewTimer(d)

	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewSource(seed))

	key := make([]byte, 16)
	const (
		N = 50
	)
	blocks := make([]byte, 16*N)
	for i := 0; ; i++ {
		select {
		case <-timer.C:
			t.Logf("iters: %d", i)
			return
		default:
		}

		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		n := rng.Intn(N-1) + 1
		blocks := blocks[:n*16]
		if _, err := rand.Read(blocks); err != nil {
			t.Fatal(err)
		}

		gcmToPolyval(t, key, blocks)
		polyvalToGCM(t, key, blocks)
	}
}

func gcmToPolyval(t *testing.T, key, blocks []byte) {
	want := gcm.New(gcm.Mulx(byteRev(key)))

	got, err := New(key)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(blocks); i += 16 {
		b := blocks[i : i+16]
		want.UpdateBlocks(byteRev(b))
		got.Update(b)
	}

	wantHash := byteRev(want.Sum(nil))
	gotHash := got.Sum(nil)
	if !bytes.Equal(wantHash, gotHash) {
		t.Fatalf("expected %x, got %x", wantHash, gotHash)
	}
}

func polyvalToGCM(t *testing.T, key, blocks []byte) {
	want := gcm.New(key)

	got, err := New(mulx(byteRev(key)))
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(blocks); i += 16 {
		b := blocks[i : i+16]
		want.UpdateBlocks(b)
		got.Update(byteRev(b))
	}

	wantHash := want.Sum(nil)
	gotHash := byteRev(got.Sum(nil))
	if !bytes.Equal(wantHash, gotHash) {
		t.Fatalf("expected %x, got %x", wantHash, gotHash)
	}
}

// mulx converts the 16-byte string s into an element of
// POLYVAL's field, multiplies it by x (doubles it), and converts
// it back.
func mulx(s []byte) []byte {
	var z fieldElement
	z.setBytes(s)
	return z.mulx().marshal()
}

// byteRev returns the 16-byte string s with its bytes reversed.
func byteRev(s []byte) []byte {
	lo := bits.ReverseBytes64(binary.LittleEndian.Uint64(s[0:8]))
	hi := bits.ReverseBytes64(binary.LittleEndian.Uint64(s[8:16]))
	r := make([]byte, 16)
	binary.LittleEndian.PutUint64(r[0:8], hi)
	binary.LittleEndian.PutUint64(r[8:16], lo)
	return r
}

// TestMulxRFCVectors tests mulx over the set of vectors from
// RFC 8452.
//
// See https://datatracker.ietf.org/doc/html/rfc8452#appendix-A
func TestMulxRFCVectors(t *testing.T) {
	for i, tc := range []struct {
		input  []byte
		output []byte
	}{
		{
			input:  unhex("01000000000000000000000000000000"),
			output: unhex("02000000000000000000000000000000"),
		},
		{
			input:  unhex("9c98c04df9387ded828175a92ba652d8"),
			output: unhex("3931819bf271fada0503eb52574ca572"),
		},
	} {
		want := tc.output
		if got := mulx(tc.input); !bytes.Equal(got, want) {
			t.Fatalf("#%d: expected %#x, got %#x", i, want, got)
		}
	}
}

// mulx doubles x in GF(2^128).
func (x fieldElement) mulx() fieldElement {
	// h := x >> 127
	h := x.hi >> (127 - 64)

	// x <<= 1
	hi := x.hi<<1 | x.lo>>(64-1)
	lo := x.lo << 1

	// v ^= h ^ (h << 127) ^ (h << 126) ^ (h << 121)
	lo ^= h
	hi ^= h << (127 - 64) // h << 127
	hi ^= h << (126 - 64) // h << 126
	hi ^= h << (121 - 64) // h << 121

	return fieldElement{hi: hi, lo: lo}
}

// marshal returns the POLYVAL field element as a 16-byte string.
func (z fieldElement) marshal() []byte {
	r := make([]byte, 16)
	binary.LittleEndian.PutUint64(r[0:8], z.lo)
	binary.LittleEndian.PutUint64(r[8:16], z.hi)
	return r
}
