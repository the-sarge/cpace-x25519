package cpace

import (
	"bytes"
	"crypto/sha512"
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"filippo.io/edwards25519/field"
)

//go:embed testdata/sage-x25519-extended.json
var sageX25519ExtendedJSON []byte

const sageX25519ExtendedJSONSHA256 = "72e2602dd8d7b5a5f46e07c1d86c637bf3cd672ac9a434cab41a40eb693487f2"

type sageExtendedFixture struct {
	Meta struct {
		Schema            int      `json:"schema"`
		SageVersion       string   `json:"sage_version"`
		ContainerImage    string   `json:"container_image"`
		ContainerDigest   string   `json:"container_digest"`
		GenerationCommand string   `json:"generation_command"`
		Notes             []string `json:"notes"`
	} `json:"meta"`
	GeneratorCases  []sageGeneratorCase  `json:"generator_cases"`
	ScalarMultCases []sageScalarMultCase `json:"scalar_mult_cases"`
	ExchangeCases   []sageExchangeCase   `json:"exchange_cases"`
}

type sageGeneratorCase struct {
	Name                string `json:"name"`
	PRS                 string `json:"prs"`
	CI                  string `json:"ci"`
	SID                 string `json:"sid"`
	H                   string `json:"h"`
	HsInBytes           int    `json:"h_s_in_bytes"`
	ZPADLength          int    `json:"zpad_length"`
	GeneratorString     string `json:"generator_string"`
	HashToField         string `json:"hash_to_field"`
	DecodedFieldElement string `json:"decoded_field_element"`
	EncodedGenerator    string `json:"encoded_generator"`
}

type sageScalarMultCase struct {
	Name          string   `json:"name"`
	Scalar        string   `json:"scalar"`
	ClampedScalar string   `json:"clamped_scalar"`
	Point         string   `json:"point"`
	DecodedU      string   `json:"decoded_u"`
	PointKind     []string `json:"point_kind"`
	Shared        string   `json:"shared"`
	VFYOK         bool     `json:"vfy_ok"`
}

type sageExchangeCase struct {
	Name            string `json:"name"`
	Password        string `json:"password"`
	InitiatorID     string `json:"initiator_id"`
	ResponderID     string `json:"responder_id"`
	Context         string `json:"context"`
	CI              string `json:"ci"`
	SID             string `json:"sid"`
	InitiatorAD     string `json:"initiator_ad"`
	ResponderAD     string `json:"responder_ad"`
	InitiatorScalar string `json:"initiator_scalar"`
	ResponderScalar string `json:"responder_scalar"`
	GeneratorString string `json:"generator_string"`
	HashToField     string `json:"hash_to_field"`
	Generator       string `json:"generator"`
	Ya              string `json:"ya"`
	Yb              string `json:"yb"`
	K               string `json:"k"`
	TranscriptIR    string `json:"transcript_ir"`
	ISKIR           string `json:"isk_ir"`
	TagA            string `json:"tag_a"`
	TagB            string `json:"tag_b"`
	SIDOutputIR     string `json:"sid_output_ir"`
	MessageA        string `json:"message_a"`
	MessageB        string `json:"message_b"`
	MessageC        string `json:"message_c"`
}

func loadSageExtendedFixture(tb testing.TB) sageExtendedFixture {
	tb.Helper()
	var fixture sageExtendedFixture
	if err := json.Unmarshal(sageX25519ExtendedJSON, &fixture); err != nil {
		tb.Fatal(err)
	}
	return fixture
}

func TestEmbeddedSageExtendedVectorJSON(t *testing.T) {
	if got := pinnedJSONHash(sageX25519ExtendedJSON); got != sageX25519ExtendedJSONSHA256 {
		t.Fatalf("Sage extended JSON SHA-256 got %s want %s", got, sageX25519ExtendedJSONSHA256)
	}
	fixture := loadSageExtendedFixture(t)
	if fixture.Meta.Schema != 1 {
		t.Fatalf("schema=%d want 1", fixture.Meta.Schema)
	}
	if fixture.Meta.SageVersion != "10.9" {
		t.Fatalf("Sage version=%q want 10.9", fixture.Meta.SageVersion)
	}
	// Keep this expectation in sync with CONTAINER_DIGEST in
	// testdata/generate_sage_x25519_vectors.sage; re-pin by regenerating the
	// JSON fixture, then updating the pinned JSON hash above.
	if fixture.Meta.ContainerDigest != "sagemath/sagemath@sha256:e068670ae5863b54b2550e72437ec637b0283acb0dc712c8584c124dbf44e667" {
		t.Fatalf("unexpected container digest %q", fixture.Meta.ContainerDigest)
	}
	if strings.Contains(fixture.Meta.ContainerImage, ":latest") {
		t.Fatalf("container image records mutable tag %q", fixture.Meta.ContainerImage)
	}
	if fixture.Meta.ContainerImage != fixture.Meta.ContainerDigest {
		t.Fatalf("container image=%q want digest-qualified reference %q", fixture.Meta.ContainerImage, fixture.Meta.ContainerDigest)
	}
	if !strings.Contains(fixture.Meta.GenerationCommand, fixture.Meta.ContainerDigest) {
		t.Fatalf("generation command %q does not contain pinned container digest %q", fixture.Meta.GenerationCommand, fixture.Meta.ContainerDigest)
	}
	if !sageFixtureNotesMentionManualDriftCheck(fixture.Meta.Notes) {
		t.Fatal("fixture metadata does not document the pinned manual drift check")
	}
	if len(fixture.GeneratorCases) != 2 || len(fixture.ScalarMultCases) != 11 || len(fixture.ExchangeCases) != 2 {
		t.Fatalf("case counts generator=%d scalar=%d exchange=%d", len(fixture.GeneratorCases), len(fixture.ScalarMultCases), len(fixture.ExchangeCases))
	}
}

func sageFixtureNotesMentionManualDriftCheck(notes []string) bool {
	for _, note := range notes {
		if strings.Contains(note, "Manual drift check") {
			return true
		}
	}
	return false
}

func TestSageGeneratorVectors(t *testing.T) {
	for _, tc := range loadSageExtendedFixture(t).GeneratorCases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.H != "SHA-512" || tc.HsInBytes != sha512BlockSize {
				t.Fatalf("unexpected hash metadata H=%q H.s_in_bytes=%d", tc.H, tc.HsInBytes)
			}
			prs := hx(t, tc.PRS)
			ci := hx(t, tc.CI)
			sid := hx(t, tc.SID)
			gotGS := generatorString([]byte(dsiX25519), prs, ci, sid, tc.HsInBytes)
			if !bytes.Equal(gotGS, hx(t, tc.GeneratorString)) {
				t.Fatalf("generator string got %x want %s", gotGS, tc.GeneratorString)
			}
			if zpadLen := tc.HsInBytes - lengthValueLen(len(prs)) - lengthValueLen(len([]byte(dsiX25519))) - 1; zpadLen != tc.ZPADLength {
				t.Fatalf("ZPAD length got %d want %d", zpadLen, tc.ZPADLength)
			}
			sum := sha512Sum(gotGS)
			if !bytes.Equal(sum[:pointSize], hx(t, tc.HashToField)) {
				t.Fatalf("hash-to-field got %x want %s", sum[:pointSize], tc.HashToField)
			}
			if decoded := x25519DecodedFieldBytes(t, sum[:pointSize]); !bytes.Equal(decoded, hx(t, tc.DecodedFieldElement)) {
				t.Fatalf("decoded field element got %x want %s", decoded, tc.DecodedFieldElement)
			}
			if got := calculateGenerator(prs, ci, sid); !bytes.Equal(got, hx(t, tc.EncodedGenerator)) {
				t.Fatalf("generator got %x want %s", got, tc.EncodedGenerator)
			}
		})
	}
}

func TestSageScalarMultVectors(t *testing.T) {
	coverage := map[string]bool{}
	for _, tc := range loadSageExtendedFixture(t).ScalarMultCases {
		t.Run(tc.Name, func(t *testing.T) {
			scalar := hx(t, tc.Scalar)
			point := hx(t, tc.Point)
			want := hx(t, tc.Shared)
			if len(scalar) != scalarSize || len(point) != pointSize || len(want) != pointSize {
				t.Fatalf("bad vector lengths scalar=%d point=%d shared=%d", len(scalar), len(point), len(want))
			}
			if clamped := clampedScalarForTest(scalar); !bytes.Equal(clamped, hx(t, tc.ClampedScalar)) {
				t.Fatalf("clamped scalar got %x want %s", clamped, tc.ClampedScalar)
			}
			if decoded := x25519DecodedFieldBytes(t, point); !bytes.Equal(decoded, hx(t, tc.DecodedU)) {
				t.Fatalf("decoded u-coordinate got %x want %s", decoded, tc.DecodedU)
			}
			got, err := scalarMult(scalar, point)
			if err != nil {
				t.Fatalf("scalarMult: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("scalarMult got %x want %x", got, want)
			}
			vfy, err := scalarMultVFY(scalar, point)
			if tc.VFYOK {
				if err != nil {
					t.Fatalf("scalarMultVFY: %v", err)
				}
				if !bytes.Equal(vfy, want) {
					t.Fatalf("scalarMultVFY got %x want %x", vfy, want)
				}
			} else {
				if vfy != nil {
					t.Fatalf("scalarMultVFY output got %x want nil", vfy)
				}
				if !errors.Is(err, ErrAbort) || !errors.Is(err, ErrPeerShareIdentity) {
					t.Fatalf("scalarMultVFY err=%v want ErrAbort and ErrPeerShareIdentity", err)
				}
			}
		})
		for _, kind := range tc.PointKind {
			switch {
			case kind == "curve", kind == "twist", kind == "low-order", kind == "non-canonical", kind == "high-bit-masked":
				coverage[kind] = true
			case strings.HasPrefix(kind, "u="):
			default:
				t.Fatalf("%s: unknown point kind label %q", tc.Name, kind)
			}
		}
	}
	for _, kind := range []string{"curve", "twist", "low-order", "non-canonical", "high-bit-masked"} {
		if !coverage[kind] {
			t.Fatalf("Sage scalar vectors missing %s coverage", kind)
		}
	}
}

func TestSageExchangeVectors(t *testing.T) {
	for _, tc := range loadSageExtendedFixture(t).ExchangeCases {
		t.Run(tc.Name, func(t *testing.T) {
			password := hx(t, tc.Password)
			initiatorID := hx(t, tc.InitiatorID)
			responderID := hx(t, tc.ResponderID)
			context := hx(t, tc.Context)
			sid := hx(t, tc.SID)
			ada := hx(t, tc.InitiatorAD)
			adb := hx(t, tc.ResponderAD)
			initScalar := hx(t, tc.InitiatorScalar)
			respScalar := hx(t, tc.ResponderScalar)

			ci := buildCI(initiatorID, responderID, context)
			if !bytes.Equal(ci, hx(t, tc.CI)) {
				t.Fatalf("CI got %x want %s", ci, tc.CI)
			}
			gotGS := generatorString([]byte(dsiX25519), password, ci, sid, sha512BlockSize)
			if !bytes.Equal(gotGS, hx(t, tc.GeneratorString)) {
				t.Fatalf("generator string got %x want %s", gotGS, tc.GeneratorString)
			}
			sum := sha512Sum(gotGS)
			if !bytes.Equal(sum[:pointSize], hx(t, tc.HashToField)) {
				t.Fatalf("hash-to-field got %x want %s", sum[:pointSize], tc.HashToField)
			}
			g := calculateGenerator(password, ci, sid)
			if !bytes.Equal(g, hx(t, tc.Generator)) {
				t.Fatalf("generator got %x want %s", g, tc.Generator)
			}

			ya, err := scalarMult(initScalar, g)
			if err != nil {
				t.Fatal(err)
			}
			yb, err := scalarMult(respScalar, g)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ya, hx(t, tc.Ya)) || !bytes.Equal(yb, hx(t, tc.Yb)) {
				t.Fatalf("shares got Ya=%x Yb=%x want Ya=%s Yb=%s", ya, yb, tc.Ya, tc.Yb)
			}
			k1, err := scalarMultVFY(initScalar, yb)
			if err != nil {
				t.Fatalf("initiator K: %v", err)
			}
			k2, err := scalarMultVFY(respScalar, ya)
			if err != nil {
				t.Fatalf("responder K: %v", err)
			}
			if !bytes.Equal(k1, hx(t, tc.K)) || !bytes.Equal(k2, hx(t, tc.K)) {
				t.Fatalf("K got %x/%x want %s", k1, k2, tc.K)
			}
			tr := newIRTranscript(ya, ada, yb, adb)
			if !bytes.Equal(tr.bytes(), hx(t, tc.TranscriptIR)) {
				t.Fatalf("transcript got %x want %s", tr.bytes(), tc.TranscriptIR)
			}
			isk := tr.deriveISK(sid, k1)
			if !bytes.Equal(isk, hx(t, tc.ISKIR)) {
				t.Fatalf("ISK got %x want %s", isk, tc.ISKIR)
			}
			if got := tr.initiatorConfirmationTag(isk, sid); !bytes.Equal(got, hx(t, tc.TagA)) {
				t.Fatalf("tagA got %x want %s", got, tc.TagA)
			}
			if got := tr.responderConfirmationTag(isk, sid); !bytes.Equal(got, hx(t, tc.TagB)) {
				t.Fatalf("tagB got %x want %s", got, tc.TagB)
			}
			if got := tr.transcriptID(); !bytes.Equal(got, hx(t, tc.SIDOutputIR)) {
				t.Fatalf("sid_output_ir got %x want %s", got, tc.SIDOutputIR)
			}

			initInput := Input{
				Password:            password,
				SelfID:              initiatorID,
				PeerID:              responderID,
				Context:             context,
				SessionID:           sid,
				LocalAssociatedData: ada,
			}
			initiator, msgA, err := startWithRandom(initInput, bytes.NewReader(initScalar))
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if !bytes.Equal(msgA, hx(t, tc.MessageA)) {
				t.Fatalf("message A got %x want %s", msgA, tc.MessageA)
			}
			respInput := Input{
				Password:            password,
				SelfID:              responderID,
				PeerID:              initiatorID,
				Context:             context,
				SessionID:           sid,
				LocalAssociatedData: adb,
			}
			responder, msgB, err := respondWithRandom(respInput, msgA, bytes.NewReader(respScalar))
			if err != nil {
				t.Fatalf("Respond: %v", err)
			}
			if !bytes.Equal(msgB, hx(t, tc.MessageB)) {
				t.Fatalf("message B got %x want %s", msgB, tc.MessageB)
			}
			msgC, initSession, err := initiator.Finish(msgB)
			if err != nil {
				t.Fatalf("initiator Finish: %v", err)
			}
			if !bytes.Equal(msgC, hx(t, tc.MessageC)) {
				t.Fatalf("message C got %x want %s", msgC, tc.MessageC)
			}
			if !bytes.Equal(initSession.state.isk, hx(t, tc.ISKIR)) {
				t.Fatalf("initiator session ISK got %x want %s", initSession.state.isk, tc.ISKIR)
			}
			respSession, err := responder.Finish(msgC)
			if err != nil {
				t.Fatalf("responder Finish: %v", err)
			}
			if !bytes.Equal(respSession.state.isk, hx(t, tc.ISKIR)) {
				t.Fatalf("responder session ISK got %x want %s", respSession.state.isk, tc.ISKIR)
			}
			if !bytes.Equal(initSession.TranscriptID(), hx(t, tc.SIDOutputIR)) || !bytes.Equal(respSession.TranscriptID(), hx(t, tc.SIDOutputIR)) {
				t.Fatalf("session TranscriptID mismatch")
			}
		})
	}
}

func sha512Sum(in []byte) [64]byte {
	return sha512.Sum512(in)
}

func clampedScalarForTest(scalar []byte) []byte {
	out := clone(scalar)
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return out
}

func x25519DecodedFieldBytes(tb testing.TB, in []byte) []byte {
	tb.Helper()
	var elem field.Element
	if _, err := elem.SetBytes(in); err != nil {
		tb.Fatal(err)
	}
	return elem.Bytes()
}
