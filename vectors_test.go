package cpace

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

//go:embed testdata/draft21-x25519-generator.json
var draft21X25519GeneratorJSON []byte

const (
	draft21X25519GeneratorJSONSHA256 = "d8f5c335146d7bfc4e1e21a154f2d4acf447445eb843e30e549cc52b5d29c13c"
	draft21X25519VectorJSONSHA256    = "7d5384bafc2144b5a73be1a7312a021bad7cb2be6a8c3e84460369ab27c838ec"
	draft21X25519LowOrderJSONSHA256  = "d6aadd0cdfaa32bae72e862ef90c63bc0f816f1a1fa64396761204cd54b7ac87"
)

type draftGeneratorVector struct {
	H               string
	HsInBytes       int
	ZPADLength      int
	PRS             []byte
	DSI             []byte
	CI              []byte
	SID             []byte
	GeneratorString []byte
	HashResult      []byte
	EncodedG        []byte
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func loadDraftGeneratorJSON(in []byte) (draftGeneratorVector, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(in, &raw); err != nil {
		return draftGeneratorVector{}, err
	}
	stringField := func(key string) (string, error) {
		var out string
		if err := json.Unmarshal(raw[key], &out); err != nil {
			return "", err
		}
		return out, nil
	}
	intField := func(key string) (int, error) {
		var out int
		if err := json.Unmarshal(raw[key], &out); err != nil {
			return 0, err
		}
		return out, nil
	}
	hexField := func(key string) ([]byte, error) {
		s, err := stringField(key)
		if err != nil {
			return nil, err
		}
		return hex.DecodeString(s)
	}
	h, err := stringField("H")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	hsInBytes, err := intField("H.s_in_bytes")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	zpadLength, err := intField("ZPAD length")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	prs, err := hexField("PRS")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	dsi, err := hexField("DSI")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	ci, err := hexField("CI")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	sid, err := hexField("sid")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	genStr, err := hexField("generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes)")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	hashResult, err := hexField("hash generator string")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	encodedG, err := hexField("generator g")
	if err != nil {
		return draftGeneratorVector{}, err
	}
	return draftGeneratorVector{
		H:               h,
		HsInBytes:       hsInBytes,
		ZPADLength:      zpadLength,
		PRS:             prs,
		DSI:             dsi,
		CI:              ci,
		SID:             sid,
		GeneratorString: genStr,
		HashResult:      hashResult,
		EncodedG:        encodedG,
	}, nil
}

func pinnedJSONHash(in []byte) string {
	sum := sha256.Sum256(bytes.TrimRight(in, "\r\n"))
	return hex.EncodeToString(sum[:])
}

func TestEmbeddedDraftVectorJSON(t *testing.T) {
	// Hashes pin the embedded fixtures to the decoded JSON blocks in draft-21
	// Appendix B.3.9 and B.3.11.1.
	if got := pinnedJSONHash(draft21X25519VectorJSON); got != draft21X25519VectorJSONSHA256 {
		t.Fatalf("vector JSON SHA-256 got %s want %s", got, draft21X25519VectorJSONSHA256)
	}
	v, err := loadDraftVectorJSON(draft21X25519VectorJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"PRS", "CI", "sid", "g", "Ya", "Yb", "K", "ISK_IR", "ISK_SY", "sid_output_ir", "sid_output_oc"} {
		if len(v[key]) == 0 {
			t.Fatalf("missing %s", key)
		}
	}
}

func TestEmbeddedDraftGeneratorJSON(t *testing.T) {
	// Hash pins the decoded JSON block in draft-21 Appendix B.1.1.1.
	if got := pinnedJSONHash(draft21X25519GeneratorJSON); got != draft21X25519GeneratorJSONSHA256 {
		t.Fatalf("generator JSON SHA-256 got %s want %s", got, draft21X25519GeneratorJSONSHA256)
	}
	v, err := loadDraftGeneratorJSON(draft21X25519GeneratorJSON)
	if err != nil {
		t.Fatal(err)
	}
	if v.H != "SHA-512" || v.HsInBytes != sha512BlockSize || v.ZPADLength != 109 {
		t.Fatalf("unexpected generator metadata H=%q H.s_in_bytes=%d ZPAD=%d", v.H, v.HsInBytes, v.ZPADLength)
	}
	gotGS := generatorString(v.DSI, v.PRS, v.CI, v.SID, v.HsInBytes)
	if !bytes.Equal(gotGS, v.GeneratorString) {
		t.Fatalf("generator_string got %x want %x", gotGS, v.GeneratorString)
	}
	sum := sha512.Sum512(v.GeneratorString)
	if !bytes.Equal(sum[:pointSize], v.HashResult) {
		t.Fatalf("hash result got %x want %x", sum[:pointSize], v.HashResult)
	}
	g := calculateGenerator(v.PRS, v.CI, v.SID)
	if !bytes.Equal(g, v.EncodedG) {
		t.Fatalf("encoded generator got %x want %x", g, v.EncodedG)
	}
}

func TestEmbeddedDraftInvalidVectorJSON(t *testing.T) {
	if got := pinnedJSONHash(draft21X25519LowOrderJSON); got != draft21X25519LowOrderJSONSHA256 {
		t.Fatalf("invalid vector JSON SHA-256 got %s want %s", got, draft21X25519LowOrderJSONSHA256)
	}
	v, err := loadDraftInvalidVectorJSON(draft21X25519LowOrderJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"Invalid Y0", "Invalid Y1", "Invalid Y2", "Invalid Y3", "Invalid Y4", "Invalid Y5", "Invalid Y7"} {
		if len(v.LowOrder[key]) != pointSize {
			t.Fatalf("%s length=%d want %d", key, len(v.LowOrder[key]), pointSize)
		}
	}
	if !bytes.Equal(v.LowOrder["Invalid Y0"], identityEncoding) {
		t.Fatalf("Invalid Y0 got %x want identity encoding", v.LowOrder["Invalid Y0"])
	}
}

func TestX25519Draft21Vectors(t *testing.T) {
	v, err := loadDraftVectorJSON(draft21X25519VectorJSON)
	if err != nil {
		t.Fatal(err)
	}
	prs := v["PRS"]
	ci := v["CI"]
	sid := v["sid"]
	gen, err := loadDraftGeneratorJSON(draft21X25519GeneratorJSON)
	if err != nil {
		t.Fatal(err)
	}
	gs := generatorString([]byte(dsiX25519), prs, ci, sid, sha512BlockSize)
	if !bytes.Equal(gs, gen.GeneratorString) {
		t.Fatalf("generator string got %x want %x", gs, gen.GeneratorString)
	}

	sum := sha512.Sum512(gs)
	if !bytes.Equal(sum[:pointSize], gen.HashResult) {
		t.Fatalf("generator hash got %x want %x", sum[:pointSize], gen.HashResult)
	}
	g := calculateGenerator(prs, ci, sid)
	wantG := v["g"]
	if !bytes.Equal(g, wantG) {
		t.Fatalf("generator got %x want %x", g, wantG)
	}
	sidMutations := []struct {
		name string
		sid  []byte
	}{
		{"first byte", func() []byte {
			out := clone(sid)
			out[0] ^= 0x01
			return out
		}()},
		{"last byte", func() []byte {
			out := clone(sid)
			out[len(out)-1] ^= 0x01
			return out
		}()},
		{"nil", nil},
		{"empty", []byte{}},
		{"appended", append(clone(sid), 0x00)},
		{"truncated", clone(sid[:len(sid)-1])},
	}
	for _, tc := range sidMutations {
		t.Run("generator sid mutation "+tc.name, func(t *testing.T) {
			alteredG := calculateGenerator(prs, ci, tc.sid)
			if bytes.Equal(alteredG, wantG) {
				t.Fatal("generator unexpectedly matched official vector after sid mutation")
			}
		})
	}

	ya, err := scalarFromCanonical(v["ya"])
	if err != nil {
		t.Fatal(err)
	}
	yb, err := scalarFromCanonical(v["yb"])
	if err != nil {
		t.Fatal(err)
	}
	Ya, err := scalarMult(ya, g)
	if err != nil {
		t.Fatal(err)
	}
	Yb, err := scalarMult(yb, g)
	if err != nil {
		t.Fatal(err)
	}
	wantYa := v["Ya"]
	wantYb := v["Yb"]
	if !bytes.Equal(Ya, wantYa) {
		t.Fatalf("Ya got %x want %x", Ya, wantYa)
	}
	if !bytes.Equal(Yb, wantYb) {
		t.Fatalf("Yb got %x want %x", Yb, wantYb)
	}

	k1, err := scalarMultVFY(ya, Yb)
	if err != nil {
		t.Fatalf("scalarMultVFY(ya,Yb): %v", err)
	}
	k2, err := scalarMultVFY(yb, Ya)
	if err != nil {
		t.Fatalf("scalarMultVFY(yb,Ya): %v", err)
	}
	wantK := v["K"]
	if !bytes.Equal(k1, wantK) || !bytes.Equal(k2, wantK) {
		t.Fatalf("K got %x/%x want %x", k1, k2, wantK)
	}

	ada := v["ADa"]
	adb := v["ADb"]
	transcriptIR := newIRTranscript(Ya, ada, Yb, adb)
	trIR := transcriptIR.bytes()
	wantTrIR := hx(t, "201d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f320341446120248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea3218562303414462")
	if !bytes.Equal(trIR, wantTrIR) {
		t.Fatalf("transcript_ir got %x want %x", trIR, wantTrIR)
	}
	iskIR := deriveISK(sid, wantK, trIR)
	wantISKIR := v["ISK_IR"]
	if !bytes.Equal(iskIR, wantISKIR) {
		t.Fatalf("ISK_IR got %x want %x", iskIR, wantISKIR)
	}
	tagA, tagB := draftVectorConfirmationTags(v)
	if got := confirmationTag(iskIR, sid, Yb, adb); !bytes.Equal(got, tagB) {
		t.Fatalf("tagB got %x want %x", got, tagB)
	}
	if got := confirmationTag(iskIR, sid, Ya, ada); !bytes.Equal(got, tagA) {
		t.Fatalf("tagA got %x want %x", got, tagA)
	}

	trOC := testTranscriptOC(Ya, ada, Yb, adb)
	iskOC := deriveISK(sid, wantK, trOC)
	wantISKOC := v["ISK_SY"]
	if !bytes.Equal(iskOC, wantISKOC) {
		t.Fatalf("ISK_SY got %x want %x", iskOC, wantISKOC)
	}

	wantSidOut := v["sid_output_ir"]
	if got := transcriptIR.transcriptID(); !bytes.Equal(got, wantSidOut) {
		t.Fatalf("sid_output got %x want %x", got, wantSidOut)
	}
	wantSidOutOC := v["sid_output_oc"]
	if got := transcriptID(trOC); !bytes.Equal(got, wantSidOutOC) {
		t.Fatalf("sid_output_oc got %x want %x", got, wantSidOutOC)
	}
}

func TestCoreDraft21Vectors(t *testing.T) {
	v, err := loadDraftVectorJSON(draft21X25519VectorJSON)
	if err != nil {
		t.Fatal(err)
	}
	tagA, tagB := draftVectorConfirmationTags(v)

	initNC := draftVectorInput(v, v["ADa"])
	defer initNC.wipe()
	initCore, gotYa, err := newInitiatorCore(initNC, &repeatingReader{buf: v["ya"]})
	if err != nil {
		t.Fatal(err)
	}
	defer clearScalar(initCore.scalar)
	if !bytes.Equal(gotYa, v["Ya"]) {
		t.Fatalf("newInitiatorCore Ya got %x want %x", gotYa, v["Ya"])
	}
	gotTagA, initSession, err := initCore.finish(v["Yb"], v["ADb"], tagB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotTagA, tagA) {
		t.Fatalf("initiator core tagA got %x want %x", gotTagA, tagA)
	}
	if !bytes.Equal(initSession.state.isk, v["ISK_IR"]) {
		t.Fatalf("initiator core session ISK got %x want %x", initSession.state.isk, v["ISK_IR"])
	}
	wantTranscriptID := v["sid_output_ir"]
	initTranscriptID := initSession.TranscriptID()
	if !bytes.Equal(initTranscriptID, wantTranscriptID) {
		t.Fatalf("initiator core session TranscriptID got %x want %x", initTranscriptID, wantTranscriptID)
	}

	respNC := draftVectorInput(v, v["ADb"])
	defer respNC.wipe()
	respCore, gotYb, gotTagB, err := newResponderCore(respNC, v["Ya"], v["ADa"], &repeatingReader{buf: v["yb"]})
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(respCore.isk)
	defer respCore.transcript.clear()
	if !bytes.Equal(gotYb, v["Yb"]) {
		t.Fatalf("newResponderCore Yb got %x want %x", gotYb, v["Yb"])
	}
	if !bytes.Equal(respCore.isk, v["ISK_IR"]) {
		t.Fatalf("responder core ISK got %x want %x", respCore.isk, v["ISK_IR"])
	}
	if !bytes.Equal(gotTagB, tagB) {
		t.Fatalf("responder core tagB got %x want %x", gotTagB, tagB)
	}
	respSession, err := respCore.finish(tagA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(respSession.state.isk, v["ISK_IR"]) {
		t.Fatalf("responder core session ISK got %x want %x", respSession.state.isk, v["ISK_IR"])
	}
	respTranscriptID := respSession.TranscriptID()
	if !bytes.Equal(respTranscriptID, wantTranscriptID) {
		t.Fatalf("responder core session TranscriptID got %x want %x", respTranscriptID, wantTranscriptID)
	}
	if !bytes.Equal(initTranscriptID, respTranscriptID) {
		t.Fatalf("core session TranscriptIDs differ: initiator %x responder %x", initTranscriptID, respTranscriptID)
	}
}

func draftVectorInput(v draftVector, ad []byte) normalizedInput {
	return normalizedInput{
		password:    clone(v["PRS"]),
		initiatorID: []byte("A_initiator"),
		responderID: []byte("B_responder"),
		ci:          clone(v["CI"]),
		sid:         clone(v["sid"]),
		ad:          clone(ad),
	}
}

func draftVectorConfirmationTags(v draftVector) (tagA, tagB []byte) {
	tr := newIRTranscript(v["Ya"], v["ADa"], v["Yb"], v["ADb"])
	isk := v["ISK_IR"]
	sid := v["sid"]
	return tr.initiatorConfirmationTag(isk, sid), tr.responderConfirmationTag(isk, sid)
}

func TestScalarMultVFYDraftInvalidVectors(t *testing.T) {
	v, err := loadDraftInvalidVectorJSON(draft21X25519LowOrderJSON)
	if err != nil {
		t.Fatal(err)
	}
	s := hx(t, "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff")
	s, err = scalarFromCanonical(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Invalid Y0", "Invalid Y1", "Invalid Y2", "Invalid Y3", "Invalid Y4", "Invalid Y5", "Invalid Y7"} {
		got, err := scalarMultVFY(s, v.LowOrder[name])
		if got != nil {
			t.Fatalf("%s: scalar_mult_vfy out=%x want nil", name, got)
		}
		if !errors.Is(err, ErrAbort) || !errors.Is(err, ErrPeerShareIdentity) {
			t.Fatalf("%s: scalar_mult_vfy err=%v want ErrAbort and ErrPeerShareIdentity", name, err)
		}
	}
	for _, tc := range []struct {
		name string
		want []byte
	}{
		{"Invalid Y6", hx(t, "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806")},
		{"Invalid Y8", hx(t, "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38")},
		{"Invalid Y9", hx(t, "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456")},
		{"Invalid Y10", hx(t, "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a")},
		{"Invalid Y11", hx(t, "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175")},
	} {
		got, err := scalarMultVFY(s, v.LowOrder[tc.name])
		if err != nil {
			t.Fatalf("%s: scalar_mult_vfy err=%v", tc.name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("%s: scalar_mult_vfy got %x want %x", tc.name, got, tc.want)
		}
	}
}
