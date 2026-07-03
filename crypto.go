package cpace

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io"
	"runtime"

	"filippo.io/edwards25519/field"
)

const (
	dsiX25519       = "CPace255"
	dsiISK          = "CPace255_ISK"
	sha512BlockSize = 128
	scalarSize      = 32
	pointSize       = 32
	tagSize         = 64
)

var identityEncoding = make([]byte, pointSize)

func generatorString(dsi, prs, ci, sid []byte, sInBytes int) []byte {
	// The trailing subtraction accounts for the length byte of the zero-padding
	// field. For this draft-21 suite, ZPAD is shorter than 128 bytes, so its
	// LEB128 length prefix is exactly one byte.
	rawZPADLen := sInBytes - lengthValueLen(len(prs)) - lengthValueLen(len(dsi)) - 1
	zpadLen := max(rawZPADLen, 0)
	return lvCat(dsi, prs, make([]byte, zpadLen), ci, sid)
}

func calculateGenerator(prs, ci, sid []byte) []byte {
	genStr := generatorString([]byte(dsiX25519), prs, ci, sid, sha512BlockSize)
	hash := sha512.Sum512(genStr)
	clearBytes(genStr)
	g := elligator2Curve25519(hash[:pointSize])
	clearBytes(hash[:])
	return g
}

func elligator2Curve25519(encodedR []byte) []byte {
	r, err := new(field.Element).SetBytes(encodedR)
	if err != nil {
		panic("cpace: invalid X25519 generator field input length")
	}

	var one, two, a, halfA field.Element
	one.One()
	setFieldElementUint64(&two, 2)
	setFieldElementUint64(&a, 486662)
	setFieldElementUint64(&halfA, 243331)

	// draft-irtf-cfrg-cpace-21 Appendix A.5:
	// v = -A / (1 + Z*r^2), where Z = 2 for Curve25519.
	var r2, denominator, v field.Element
	r2.Square(r)
	denominator.Multiply(&two, &r2)
	denominator.Add(&denominator, &one)
	v.Invert(&denominator)
	v.Multiply(&v, &a)
	v.Negate(&v)

	var v2, v3, av2, rhs field.Element
	v2.Square(&v)
	v3.Multiply(&v2, &v)
	av2.Multiply(&a, &v2)
	rhs.Add(&v3, &av2)
	rhs.Add(&rhs, &v)

	_, wasSquare := new(field.Element).SqrtRatio(&rhs, &one)
	var zero, squareX, nonSquareX, zeroX, x field.Element
	squareX.Set(&v)
	nonSquareX.Negate(&v)
	nonSquareX.Subtract(&nonSquareX, &a)
	zeroX.Negate(&halfA)

	x.Select(&squareX, &nonSquareX, wasSquare)
	x.Select(&zeroX, &x, rhs.Equal(&zero))
	return x.Bytes()
}

func setFieldElementUint64(v *field.Element, n uint64) {
	var b [pointSize]byte
	for i := range 8 {
		b[i] = byte(n >> (8 * i))
	}
	if _, err := v.SetBytes(b[:]); err != nil {
		panic("cpace: invalid field constant")
	}
}

func sampleScalar(r io.Reader) ([]byte, error) {
	b := make([]byte, scalarSize)
	if _, err := io.ReadFull(r, b); err != nil {
		clearBytes(b)
		return nil, fmt.Errorf("%w: scalar randomness: %w", ErrRandomness, err)
	}
	return b, nil
}

//go:noinline
func clearScalar(s []byte) {
	if s == nil {
		return
	}
	clearBytes(s)
	runtime.KeepAlive(s)
}

func scalarFromCanonical(b []byte) ([]byte, error) {
	if len(b) != scalarSize {
		return nil, fmt.Errorf("%w: scalar length", ErrInvalidInput)
	}
	return clone(b), nil
}

func scalarMult(s, p []byte) ([]byte, error) {
	return x25519ScalarMult(s, p)
}

func x25519ScalarMult(scalar, point []byte) ([]byte, error) {
	if len(scalar) != scalarSize {
		return nil, fmt.Errorf("%w: scalar length", ErrInvalidInput)
	}
	if len(point) != pointSize {
		return nil, fmt.Errorf("%w: invalid peer share length", ErrAbort)
	}

	var e [scalarSize]byte
	copy(e[:], scalar)
	e[0] &= 248
	e[31] &= 127
	e[31] |= 64

	var x1, x2, z2, x3, z3, tmp0, tmp1 field.Element
	if _, err := x1.SetBytes(point); err != nil {
		panic("cpace: invalid X25519 point length after size check")
	}
	x2.One()
	x3.Set(&x1)
	z3.One()

	swap := 0
	for pos := 254; pos >= 0; pos-- {
		b := e[pos/8] >> uint(pos&7)
		b &= 1
		swap ^= int(b)
		x2.Swap(&x3, swap)
		z2.Swap(&z3, swap)
		swap = int(b)

		tmp0.Subtract(&x3, &z3)
		tmp1.Subtract(&x2, &z2)
		x2.Add(&x2, &z2)
		z2.Add(&x3, &z3)
		z3.Multiply(&tmp0, &x2)
		z2.Multiply(&z2, &tmp1)
		tmp0.Square(&tmp1)
		tmp1.Square(&x2)
		x3.Add(&z3, &z2)
		z2.Subtract(&z3, &z2)
		x2.Multiply(&tmp1, &tmp0)
		tmp1.Subtract(&tmp1, &tmp0)
		z2.Square(&z2)

		z3.Mult32(&tmp1, 121666)
		x3.Square(&x3)
		tmp0.Add(&tmp0, &z3)
		z3.Multiply(&x1, &z2)
		z2.Multiply(&tmp1, &tmp0)
	}

	x2.Swap(&x3, swap)
	z2.Swap(&z3, swap)
	z2.Invert(&z2)
	x2.Multiply(&x2, &z2)
	out := x2.Bytes()
	clearBytes(e[:])
	return out, nil
}

func deriveISK(sid, k, transcript []byte) []byte {
	// lvCat fixes the DSI, sid, and K boundaries. The remaining raw transcript
	// is injective for the public initiator-responder flow because
	// newIRTranscript has a fixed sequence of length-value fields.
	prefix := lvCat([]byte(dsiISK), sid, k)
	material := make([]byte, len(prefix)+len(transcript))
	copy(material, prefix)
	copy(material[len(prefix):], transcript)
	clearBytes(prefix)
	sum := sha512.Sum512(material)
	clearBytes(material)
	out := make([]byte, sha512.Size)
	copy(out, sum[:])
	clearBytes(sum[:])
	return out
}

func confirmationTag(isk, sid, y, ad []byte) []byte {
	keyInput := append([]byte("CPaceMac"), sid...)
	// Raw concatenation follows draft-21 §10.4. It is collision-free because
	// ISK is always exactly 64 bytes (SHA-512 output), so the boundary between
	// sid and ISK is recoverable as the last 64 bytes. Two different
	// (sid, ISK) pairs collide only if len(sid_1) = len(sid_2) and
	// sid_1 || ISK_1 = sid_2 || ISK_2 — i.e. sid_1 = sid_2 and ISK_1 = ISK_2,
	// which is the same session.
	keyInput = append(keyInput, isk...)
	macKey := sha512.Sum512(keyInput)
	clearBytes(keyInput)
	m := hmac.New(sha512.New, macKey[:])
	clearBytes(macKey[:])
	_, _ = m.Write(lvCat(y, ad))
	return m.Sum(nil)
}

//go:noinline
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
