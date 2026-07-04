package cpace

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
)

//go:embed testdata/draft21-x25519-sha512.json
var draft21X25519VectorJSON []byte

//go:embed testdata/draft21-x25519-low-order.json
var draft21X25519LowOrderJSON []byte

const fuzzProtocolInputCap = 4096

type draftVector map[string][]byte

type draftInvalidVector struct {
	Valid     map[string][]byte
	InvalidY1 []byte
	InvalidY2 []byte
	LowOrder  map[string][]byte
}

type testFatalf interface {
	Fatalf(format string, args ...any)
}

func markTestHelper(tb any) {
	if h, ok := tb.(interface{ Helper() }); ok {
		h.Helper()
	}
}

type exchangeFixture struct {
	tb        testFatalf
	initiator *Initiator
	responder *Responder
	msgA      []byte
	msgB      []byte
}

type repeatingReader struct {
	buf []byte
	off int
}

func (r *repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		if len(r.buf) == 0 {
			p[i] = 1
			continue
		}
		p[i] = r.buf[r.off%len(r.buf)]
		r.off++
	}
	return len(p), nil
}

func repeatingRand(fill byte) io.Reader {
	return &repeatingReader{buf: bytes.Repeat([]byte{fill}, scalarSize)}
}

func testInitiatorInput() Input {
	return Input{
		Password:  []byte("password"),
		SelfID:    []byte("initiator"),
		PeerID:    []byte("responder"),
		Context:   []byte("context"),
		SessionID: []byte("sid"),
	}
}

func testResponderInput() Input {
	return Input{
		Password:  []byte("password"),
		SelfID:    []byte("responder"),
		PeerID:    []byte("initiator"),
		Context:   []byte("context"),
		SessionID: []byte("sid"),
	}
}

func defaultExchangeInputs() (Input, Input) {
	initInput := testInitiatorInput()
	initInput.LocalAssociatedData = []byte("ADa")
	respInput := testResponderInput()
	respInput.LocalAssociatedData = []byte("ADb")
	return initInput, respInput
}

func startTestInitiator(cfg Input) (*Initiator, []byte, error) {
	return startWithRandom(cfg, repeatingRand(0x11))
}

func respondTestResponder(cfg Input, messageA []byte) (*Responder, []byte, error) {
	return respondWithRandom(cfg, messageA, repeatingRand(0x22))
}

func newExchange(tb testFatalf, initInput, respInput Input) *exchangeFixture {
	markTestHelper(tb)
	initiator, msgA, err := startTestInitiator(initInput)
	if err != nil {
		tb.Fatalf("Start failed for fixed exchange config: %v", err)
	}
	responder, msgB, err := respondTestResponder(respInput, msgA)
	if err != nil {
		tb.Fatalf("Respond failed for fixed exchange config: %v", err)
	}
	return &exchangeFixture{
		tb:        tb,
		initiator: initiator,
		responder: responder,
		msgA:      msgA,
		msgB:      msgB,
	}
}

func (x *exchangeFixture) finishInitiator() ([]byte, *Session) {
	markTestHelper(x.tb)
	msgC, session, err := x.initiator.Finish(x.msgB)
	if err != nil {
		x.tb.Fatalf("initiator Finish failed for fixed exchange config: %v", err)
	}
	return msgC, session
}

func (x *exchangeFixture) finishResponder(msgC []byte) *Session {
	markTestHelper(x.tb)
	session, err := x.responder.Finish(msgC)
	if err != nil {
		x.tb.Fatalf("responder Finish failed for fixed exchange config: %v", err)
	}
	return session
}

func (x *exchangeFixture) complete() (*Session, *Session) {
	markTestHelper(x.tb)
	msgC, initSession := x.finishInitiator()
	respSession := x.finishResponder(msgC)
	return initSession, respSession
}

func loadDraftVectorJSON(in []byte) (draftVector, error) {
	var raw map[string]string
	if err := json.Unmarshal(in, &raw); err != nil {
		return nil, err
	}
	out := make(draftVector, len(raw))
	for k, v := range raw {
		decoded, err := hex.DecodeString(v)
		if err != nil {
			return nil, err
		}
		out[k] = decoded
	}
	return out, nil
}

func loadDraftInvalidVectorJSON(in []byte) (draftInvalidVector, error) {
	var raw map[string]string
	if err := json.Unmarshal(in, &raw); err != nil {
		return draftInvalidVector{}, err
	}
	lowOrder := make(map[string][]byte, len(raw))
	for k, v := range raw {
		decoded, err := hex.DecodeString(v)
		if err != nil {
			return draftInvalidVector{}, err
		}
		lowOrder[k] = decoded
	}
	vector, err := loadDraftVectorJSON(draft21X25519VectorJSON)
	if err != nil {
		return draftInvalidVector{}, err
	}
	valid := map[string][]byte{
		"s":                        vector["ya"],
		"X":                        vector["Yb"],
		"G.scalar_mult_vfy(s,X)":   vector["K"],
		"G_X25519.scalar_mult_vfy": vector["K"],
		"G.scalar_mult_vfy(ya,Yb)": vector["K"],
		"G.scalar_mult_vfy(yb,Ya)": vector["K"],
	}
	return draftInvalidVector{
		Valid:     valid,
		InvalidY1: lowOrder["Invalid Y1"],
		InvalidY2: lowOrder["Invalid Y0"],
		LowOrder:  lowOrder,
	}, nil
}

func FuzzDecodeMessageA(f *testing.F) {
	initInput, respInput := defaultExchangeInputs()
	exchange := newExchange(f, initInput, respInput)
	invalid := fuzzDraftInvalidVector(f)
	for _, seed := range messageAFuzzSeeds(exchange.msgA, exchange.msgB, invalid.InvalidY1) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = decodeMessageA(in)
	})
}

func FuzzDecodeMessageB(f *testing.F) {
	initInput, respInput := defaultExchangeInputs()
	exchange := newExchange(f, initInput, respInput)
	msgC, _ := exchange.finishInitiator()
	invalid := fuzzDraftInvalidVector(f)
	for _, seed := range messageBFuzzSeeds(exchange.msgB, msgC, invalid.InvalidY1) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = decodeMessageB(in)
	})
}

func FuzzDecodeMessageC(f *testing.F) {
	initInput, respInput := defaultExchangeInputs()
	exchange := newExchange(f, initInput, respInput)
	msgC, _ := exchange.finishInitiator()
	for _, seed := range messageCFuzzSeeds(msgC, exchange.msgA) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = decodeMessageC(in)
	})
}

func FuzzDraftVectorJSONLoader(f *testing.F) {
	f.Add(draft21X25519VectorJSON)
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = loadDraftVectorJSON(in)
	})
}

func FuzzDraftInvalidVectorJSONLoader(f *testing.F) {
	f.Add(draft21X25519LowOrderJSON)
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = loadDraftInvalidVectorJSON(in)
	})
}

func FuzzProtocolConsistency(f *testing.F) {
	f.Add([]byte("sid"), []byte("ctx"), []byte("ADa"), []byte("ADb"))
	f.Add([]byte("sid2"), []byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, sid, ctx, ada, adb []byte) {
		if len(sid) == 0 || len(sid) > sessionIDCap.length || len(ctx) > contextCap.length || len(ada) > 1024 || len(adb) > 1024 {
			t.Skip()
		}
		initCfg := Input{
			Password:            []byte("password"),
			SelfID:              []byte("initiator"),
			PeerID:              []byte("responder"),
			Context:             ctx,
			SessionID:           sid,
			LocalAssociatedData: ada,
		}
		respCfg := Input{
			Password:            []byte("password"),
			SelfID:              []byte("responder"),
			PeerID:              []byte("initiator"),
			Context:             ctx,
			SessionID:           sid,
			LocalAssociatedData: adb,
		}
		initiator, msgA, err := startTestInitiator(initCfg)
		if err != nil {
			t.Fatalf("Start failed for bounded valid input: %v", err)
		}
		responder, msgB, err := respondTestResponder(respCfg, msgA)
		if err != nil {
			t.Fatalf("Respond failed for matching input: %v", err)
		}
		msgC, sI, err := initiator.Finish(msgB)
		if err != nil {
			t.Fatalf("initiator Finish failed for matching input: %v", err)
		}
		sR, err := responder.Finish(msgC)
		if err != nil {
			t.Fatalf("responder finish failed after initiator confirmation: %v", err)
		}
		if !bytes.Equal(sI.TranscriptID(), sR.TranscriptID()) {
			t.Fatalf("transcript mismatch")
		}
	})
}

func FuzzProtocolMismatch(f *testing.F) {
	f.Add([]byte("sid"), []byte("ctx"), []byte("ADa"), []byte("ADb"))
	f.Add([]byte("sid2"), []byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, sid, ctx, ada, adb []byte) {
		// respCfg.Context appends one byte below; ada/adb use a fuzz-budget cap.
		if len(sid) == 0 || len(sid) > sessionIDCap.length || len(ctx) >= contextCap.length || len(ada) > 1024 || len(adb) > 1024 {
			t.Skip()
		}
		initCfg := Input{
			Password:            []byte("password"),
			SelfID:              []byte("initiator"),
			PeerID:              []byte("responder"),
			Context:             ctx,
			SessionID:           sid,
			LocalAssociatedData: ada,
		}
		respCfg := Input{
			Password:            []byte("password"),
			SelfID:              []byte("responder"),
			PeerID:              []byte("initiator"),
			Context:             append(clone(ctx), 0xff),
			SessionID:           sid,
			LocalAssociatedData: adb,
		}
		initiator, msgA, err := startTestInitiator(initCfg)
		if err != nil {
			t.Fatalf("Start failed for bounded valid input: %v", err)
		}
		_, msgB, err := respondTestResponder(respCfg, msgA)
		if err != nil {
			t.Fatalf("Respond failed before expected confirmation mismatch: %v", err)
		}
		if _, _, err := initiator.Finish(msgB); !errors.Is(err, ErrConfirmationFailed) {
			t.Fatalf("Finish err=%v", err)
		}
	})
}

func FuzzRespondWithFuzzedMessageA(f *testing.F) {
	initInput, respInput := defaultExchangeInputs()
	exchange := newExchange(f, initInput, respInput)
	invalid := fuzzDraftInvalidVector(f)
	for _, seed := range messageAProtocolFuzzSeeds(exchange.msgA, exchange.msgB, invalid.InvalidY1) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, messageA []byte) {
		if len(messageA) > fuzzProtocolInputCap {
			t.Skip()
		}
		_, respInput := defaultExchangeInputs()
		_, msgB, err := respondWithRandom(respInput, messageA, repeatingRand(0x22))
		if err == nil {
			if _, err := decodeMessageB(msgB); err != nil {
				t.Fatalf("Respond returned malformed message B: %v", err)
			}
		}
	})
}

func FuzzInitiatorFinishWithFuzzedMessageB(f *testing.F) {
	initInput, respInput := defaultExchangeInputs()
	exchange := newExchange(f, initInput, respInput)
	msgC, _ := exchange.finishInitiator()
	invalid := fuzzDraftInvalidVector(f)
	for _, seed := range messageBFuzzSeeds(exchange.msgB, msgC, invalid.InvalidY1) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, messageB []byte) {
		if len(messageB) > fuzzProtocolInputCap {
			t.Skip()
		}
		initInput, _ := defaultExchangeInputs()
		initiator, _, err := startTestInitiator(initInput)
		if err != nil {
			t.Fatalf("Start failed for fixed fuzz config: %v", err)
		}
		msgC, sess, err := initiator.Finish(messageB)
		if err == nil {
			if sess == nil {
				t.Fatalf("Finish returned nil session without error")
			}
			if _, err := decodeMessageC(msgC); err != nil {
				t.Fatalf("Finish returned malformed message C: %v", err)
			}
		}
	})
}

func FuzzResponderFinishWithFuzzedMessageC(f *testing.F) {
	initInput, respInput := defaultExchangeInputs()
	exchange := newExchange(f, initInput, respInput)
	msgC, _ := exchange.finishInitiator()
	for _, seed := range messageCFuzzSeeds(msgC, exchange.msgA) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, messageC []byte) {
		if len(messageC) > fuzzProtocolInputCap {
			t.Skip()
		}
		initInput, respInput := defaultExchangeInputs()
		exchange := newExchange(t, initInput, respInput)
		sess, err := exchange.responder.Finish(messageC)
		if err == nil && sess == nil {
			t.Fatalf("Finish returned nil session without error")
		}
	})
}

func FuzzScalarMultVFY(f *testing.F) {
	invalid := fuzzDraftInvalidVector(f)
	validX := invalid.Valid["X"]
	if len(validX) == pointSize {
		f.Add(validX)
		f.Add(validX[:pointSize-1])
	}
	if len(invalid.InvalidY1) > 0 {
		f.Add(invalid.InvalidY1)
	}
	if len(invalid.InvalidY2) > 0 {
		f.Add(invalid.InvalidY2)
	}
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, pointSize))

	s, err := scalarFromCanonical(invalid.Valid["s"])
	if err != nil {
		f.Fatalf("invalid scalar fixture: %v", err)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 128 {
			t.Skip()
		}
		out, err := scalarMultVFY(s, encoded)
		if err == nil {
			if len(out) != pointSize {
				t.Fatalf("scalarMultVFY output length=%d", len(out))
			}
			if bytes.Equal(out, identityEncoding) {
				t.Fatalf("scalarMultVFY accepted identity output")
			}
			return
		}
		if out != nil {
			t.Fatalf("scalarMultVFY rejection out=%x want nil", out)
		}
		if !errors.Is(err, ErrAbort) {
			t.Fatalf("scalarMultVFY rejection err=%v does not wrap ErrAbort", err)
		}
		switch {
		case len(encoded) != pointSize:
			if errors.Is(err, ErrPeerShareEncoding) || errors.Is(err, ErrPeerShareIdentity) {
				t.Fatalf("length rejection err=%v wraps a peer-share sentinel", err)
			}
		default:
			if !errors.Is(err, ErrPeerShareIdentity) || errors.Is(err, ErrPeerShareEncoding) {
				t.Fatalf("low-order rejection err=%v want ErrPeerShareIdentity only", err)
			}
		}
	})
}

func FuzzMessageARoundTrip(f *testing.F) {
	f.Add([]byte("sid"), exactMessageFieldBytes(messageASpec, pointSize, 0x42, 0), []byte("ADa"))
	f.Add([]byte{}, identityEncoding, []byte{})
	f.Add(bytes.Repeat([]byte{0x01}, 8), exactMessageFieldBytes(messageASpec, pointSize, 0x02, -1), bytes.Repeat([]byte{0x03}, 8))
	f.Fuzz(func(t *testing.T, sid, ya, ada []byte) {
		if len(sid) > fuzzProtocolInputCap || len(ya) > fuzzProtocolInputCap || len(ada) > fuzzProtocolInputCap {
			t.Skip()
		}
		msg := encodeMessageA(sid, ya, ada)
		got, err := decodeMessageA(msg)
		if !messageFieldsMatchFramingShape(messageASpec, sid, ya, ada) {
			if err == nil {
				t.Fatalf("decodeMessageA accepted lengths sid=%d ya=%d ada=%d", len(sid), len(ya), len(ada))
			}
			return
		}
		if err != nil {
			t.Fatalf("decodeMessageA round trip failed: %v", err)
		}
		if !bytes.Equal(got.sid, sid) || !bytes.Equal(got.ya, ya) || !bytes.Equal(got.ada, ada) {
			t.Fatalf("message A round trip mismatch")
		}
	})
}

func FuzzMessageBRoundTrip(f *testing.F) {
	f.Add(exactMessageFieldBytes(messageBSpec, pointSize, 0x42, 0), []byte("ADb"), exactMessageFieldBytes(messageBSpec, tagSize, 0x99, 0))
	f.Add(identityEncoding, []byte{}, exactMessageFieldBytes(messageBSpec, tagSize, 0x00, 0))
	f.Add(exactMessageFieldBytes(messageBSpec, pointSize, 0x02, -1), bytes.Repeat([]byte{0x03}, 8), exactMessageFieldBytes(messageBSpec, tagSize, 0x04, -1))
	f.Fuzz(func(t *testing.T, yb, adb, tag []byte) {
		if len(yb) > fuzzProtocolInputCap || len(adb) > fuzzProtocolInputCap || len(tag) > fuzzProtocolInputCap {
			t.Skip()
		}
		msg := encodeMessageB(yb, adb, tag)
		got, err := decodeMessageB(msg)
		if !messageFieldsMatchFramingShape(messageBSpec, yb, adb, tag) {
			if err == nil {
				t.Fatalf("decodeMessageB accepted lengths yb=%d adb=%d tag=%d", len(yb), len(adb), len(tag))
			}
			return
		}
		if err != nil {
			t.Fatalf("decodeMessageB round trip failed: %v", err)
		}
		if !bytes.Equal(got.yb, yb) || !bytes.Equal(got.adb, adb) || !bytes.Equal(got.tag, tag) {
			t.Fatalf("message B round trip mismatch")
		}
	})
}

func FuzzMessageCRoundTrip(f *testing.F) {
	f.Add(exactMessageFieldBytes(messageCSpec, tagSize, 0x99, 0))
	f.Add(exactMessageFieldBytes(messageCSpec, tagSize, 0x00, 0))
	f.Add(exactMessageFieldBytes(messageCSpec, tagSize, 0x04, -1))
	f.Fuzz(func(t *testing.T, tag []byte) {
		if len(tag) > fuzzProtocolInputCap {
			t.Skip()
		}
		msg := encodeMessageC(tag)
		got, err := decodeMessageC(msg)
		if !messageFieldsMatchFramingShape(messageCSpec, tag) {
			if err == nil {
				t.Fatalf("decodeMessageC accepted tag length %d", len(tag))
			}
			return
		}
		if err != nil {
			t.Fatalf("decodeMessageC round trip failed: %v", err)
		}
		if !bytes.Equal(got.tag, tag) {
			t.Fatalf("message C round trip mismatch")
		}
	})
}

func messageAFuzzSeeds(validA, crossRoleB, invalidY []byte) [][]byte {
	return messageFuzzSeeds(messageASpec, validA, crossRoleB, invalidY)
}

func messageAProtocolFuzzSeeds(validA, crossRoleB, invalidY []byte) [][]byte {
	seeds := messageAFuzzSeeds(validA, crossRoleB, invalidY)
	seeds = append(seeds, messageWithDecodedField(messageASpec, validA, 0, []byte("other sid")))
	return seeds
}

func messageBFuzzSeeds(validB, crossRoleC, invalidY []byte) [][]byte {
	return messageFuzzSeeds(messageBSpec, validB, crossRoleC, invalidY)
}

func messageCFuzzSeeds(validC, crossRoleA []byte) [][]byte {
	return messageFuzzSeeds(messageCSpec, validC, crossRoleA, nil)
}

func messageFuzzSeeds(spec messageSpec, valid, crossRole, invalidY []byte) [][]byte {
	seeds := [][]byte{
		clone(valid),
		truncatedMessage(valid),
		withMessageRole(valid, otherMessageRole(spec.role)),
		append(messageHeader(spec.role), 0x80, 0x00),
	}
	if pointIndex, ok := spec.exactFieldIndex(pointSize); ok {
		seeds = append(seeds, messageWithDecodedField(spec, valid, pointIndex, identityEncoding))
		if invalidY != nil {
			seeds = append(seeds, messageWithDecodedField(spec, valid, pointIndex, invalidY))
		}
	}
	if tagIndex, ok := spec.exactFieldIndex(tagSize); ok {
		seeds = append(seeds, messageWithDecodedField(spec, valid, tagIndex, bytes.Repeat([]byte{0x99}, tagSize-1)))
		seeds = append(seeds, withMessageTamperedLastByte(valid))
	}
	seeds = append(seeds, clone(crossRole))
	return seeds
}

func (spec messageSpec) exactFieldIndex(length int) (int, bool) {
	found := -1
	foundName := ""
	for i, field := range spec.fields {
		if field.exact && field.length == length {
			if found >= 0 {
				panic(fmt.Sprintf("cpace test: %s has ambiguous exact %d-byte field: %s and %s", spec.name, length, foundName, field.name))
			}
			found = i
			foundName = field.name
		}
	}
	if found < 0 {
		return 0, false
	}
	return found, true
}

func exactMessageFieldBytes(spec messageSpec, length int, fill byte, delta int) []byte {
	i, ok := spec.exactFieldIndex(length)
	if !ok {
		panic("cpace test: exact message field missing from catalogue")
	}
	n := max(spec.fields[i].length+delta, 0)
	return bytes.Repeat([]byte{fill}, n)
}

func messageWithDecodedField(spec messageSpec, msg []byte, fieldIndex int, value []byte) []byte {
	fields, err := spec.decode(msg)
	if err != nil {
		panic(fmt.Sprintf("cpace test: valid %s message failed to decode: %v", spec.name, err))
	}
	fields[fieldIndex] = value
	return spec.encode(fields...)
}

func (spec messageSpec) acceptsFieldLengths(fields ...[]byte) bool {
	if len(fields) != len(spec.fields) {
		return false
	}
	remainingSpecs := spec.fields
	for _, got := range fields {
		field := remainingSpecs[0]
		remainingSpecs = remainingSpecs[1:]
		if err := field.validateMessageLength(len(got)); err != nil {
			return false
		}
	}
	return true
}

func messageFieldsMatchFramingShape(spec messageSpec, fields ...[]byte) bool {
	if len(fields) != len(spec.fields) {
		return false
	}
	// Keep this independent from acceptsFieldLengths and validateMessageLength so round-trip fuzzers can detect decoder acceptance drift.
	remainingSpecs := spec.fields
	for _, got := range fields {
		field := remainingSpecs[0]
		remainingSpecs = remainingSpecs[1:]
		gotLength := len(got)
		if field.exact {
			if gotLength != field.length {
				return false
			}
			continue
		}
		if gotLength > field.length {
			return false
		}
	}
	return true
}

func messageHeader(role byte) []byte {
	return []byte{wireFormatV1, wireSuite, role}
}

func withMessageRole(msg []byte, role byte) []byte {
	out := clone(msg)
	if len(out) > 2 {
		out[2] = role
	}
	return out
}

func withMessageTamperedLastByte(msg []byte) []byte {
	out := clone(msg)
	if len(out) > 0 {
		out[len(out)-1] ^= 0x01
	}
	return out
}

func truncatedMessage(msg []byte) []byte {
	if len(msg) == 0 {
		return nil
	}
	return clone(msg[:len(msg)-1])
}

func otherMessageRole(role byte) byte {
	for _, spec := range messageFramingCatalogue() {
		if spec.role != role {
			return spec.role
		}
	}
	return 0xff
}

func fuzzDraftInvalidVector(tb testFatalf) draftInvalidVector {
	markTestHelper(tb)
	v, err := loadDraftInvalidVectorJSON(draft21X25519LowOrderJSON)
	if err != nil {
		tb.Fatalf("invalid vector fixture failed to load: %v", err)
	}
	return v
}
