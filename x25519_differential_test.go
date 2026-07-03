package cpace

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

// RFC 7748 section 5.2 X25519 known answers, transcribed verbatim from
// https://www.rfc-editor.org/rfc/rfc7748.txt. These pin the package-local
// Montgomery ladder to the RFC directly, independent of the draft-21 CPace
// fixtures. The second vector's u-coordinate has its top bit set, so it also
// pins the RFC-required masking of the most significant input bit.
const (
	rfc7748Scalar1 = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
	rfc7748U1      = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
	rfc7748Out1    = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

	rfc7748Scalar2 = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
	rfc7748U2      = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
	rfc7748Out2    = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"

	rfc7748Iterated1    = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
	rfc7748Iterated1000 = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
	rfc7748Iterated1M   = "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
)

func x25519BasepointEncoding() []byte {
	b := make([]byte, pointSize)
	b[0] = 9
	return b
}

func TestX25519RFC7748Vectors(t *testing.T) {
	for _, tc := range []struct {
		name           string
		scalar, u, out string
	}{
		{"vector1", rfc7748Scalar1, rfc7748U1, rfc7748Out1},
		{"vector2", rfc7748Scalar2, rfc7748U2, rfc7748Out2},
	} {
		scalar := hx(t, tc.scalar)
		u := hx(t, tc.u)
		want := hx(t, tc.out)

		got, err := scalarMult(scalar, u)
		if err != nil {
			t.Fatalf("%s: scalarMult: %v", tc.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: scalarMult got %x want %x", tc.name, got, want)
		}

		ref, err := ecdhX25519(scalar, u)
		if err != nil {
			t.Fatalf("%s: crypto/ecdh: %v", tc.name, err)
		}
		if !bytes.Equal(ref, want) {
			t.Fatalf("%s: crypto/ecdh got %x want %x", tc.name, ref, want)
		}
	}
}

// TestX25519RFC7748IteratedVectors runs the RFC 7748 section 5.2 iterated
// procedure: starting from k = u = the basepoint encoding, each round computes
// X25519(k, u) and shifts k into u. The 1,000,000-iteration checkpoint takes
// on the order of a minute, so it only runs when CPACE_RFC7748_FULL is set.
func TestX25519RFC7748IteratedVectors(t *testing.T) {
	checkpoints := map[int]string{
		1:    rfc7748Iterated1,
		1000: rfc7748Iterated1000,
	}
	iterations := 1000
	if os.Getenv("CPACE_RFC7748_FULL") != "" {
		checkpoints[1_000_000] = rfc7748Iterated1M
		iterations = 1_000_000
	}

	k := x25519BasepointEncoding()
	u := x25519BasepointEncoding()
	for i := 1; i <= iterations; i++ {
		next, err := scalarMult(k, u)
		if err != nil {
			t.Fatalf("iteration %d: scalarMult: %v", i, err)
		}
		u, k = k, next
		if want, ok := checkpoints[i]; ok {
			if got := hex.EncodeToString(k); got != want {
				t.Fatalf("after %d iterations got %s want %s", i, got, want)
			}
		}
	}
}

// ecdhX25519 is the reference oracle: the standard library's X25519 via
// crypto/ecdh. Its only error condition for exact-size inputs is the all-zero
// shared secret from a low-order point.
func ecdhX25519(scalar, point []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(point)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// FuzzX25519DifferentialECDH holds the package-local ladder and crypto/ecdh
// to the same answers on the full 32-byte scalar and point input space, and
// holds scalarMultVFY's low-order rejection to crypto/ecdh's error condition.
// The two implementations share field-arithmetic lineage, so agreement rules
// out transcription and drift divergence, not shared-ancestor design flaws;
// those remain with the hash-pinned draft fixtures and independent review.
func FuzzX25519DifferentialECDH(f *testing.F) {
	invalid := fuzzDraftInvalidVector(f)
	seedScalar := invalid.Valid["s"]
	if len(seedScalar) != scalarSize {
		f.Fatalf("invalid scalar fixture length=%d", len(seedScalar))
	}
	f.Add(hx(f, rfc7748Scalar1), hx(f, rfc7748U1))
	f.Add(hx(f, rfc7748Scalar2), hx(f, rfc7748U2))
	f.Add(hx(f, rfc7748Scalar1), x25519BasepointEncoding())
	if validX := invalid.Valid["X"]; len(validX) == pointSize {
		f.Add(seedScalar, validX)
	}
	// One rejected low-order encoding and one accepted non-canonical encoding
	// from the draft fixture, so both oracle branches have seed coverage.
	for _, name := range []string{"Invalid Y2", "Invalid Y6"} {
		if p := invalid.LowOrder[name]; len(p) == pointSize {
			f.Add(seedScalar, p)
		}
	}
	f.Add(make([]byte, scalarSize), make([]byte, pointSize))
	f.Add(bytes.Repeat([]byte{0xff}, scalarSize), bytes.Repeat([]byte{0xff}, pointSize))

	f.Fuzz(func(t *testing.T, scalar, point []byte) {
		if len(scalar) != scalarSize || len(point) != pointSize {
			t.Skip()
		}
		ours, err := scalarMult(scalar, point)
		if err != nil {
			t.Fatalf("scalarMult(%x, %x): %v", scalar, point, err)
		}
		ref, refErr := ecdhX25519(scalar, point)
		vfyOut, vfyErr := scalarMultVFY(scalar, point)
		if refErr != nil {
			if !bytes.Equal(ours, identityEncoding) {
				t.Fatalf("ecdh rejected (%v) but ladder output %x is not the identity encoding: scalar=%x point=%x", refErr, ours, scalar, point)
			}
			if vfyOut != nil || !errors.Is(vfyErr, ErrAbort) || !errors.Is(vfyErr, ErrPeerShareIdentity) {
				t.Fatalf("ecdh rejected (%v) but scalarMultVFY out=%x err=%v: scalar=%x point=%x", refErr, vfyOut, vfyErr, scalar, point)
			}
			return
		}
		if !bytes.Equal(ours, ref) {
			t.Fatalf("ladder disagreement: scalar=%x point=%x ladder=%x ecdh=%x", scalar, point, ours, ref)
		}
		if vfyErr != nil {
			t.Fatalf("ecdh accepted but scalarMultVFY rejected: %v: scalar=%x point=%x", vfyErr, scalar, point)
		}
		if !bytes.Equal(vfyOut, ref) {
			t.Fatalf("scalarMultVFY output %x != ecdh %x: scalar=%x point=%x", vfyOut, ref, scalar, point)
		}
	})
}
