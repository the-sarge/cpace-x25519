package cpace_test

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/the-sarge/cpace-x25519"
)

func Example() {
	initCfg := exampleInitiatorInput("session-1234")
	initCfg.LocalAssociatedData = []byte("client hello")
	initiator, msgA, err := cpace.Start(initCfg)
	if err != nil {
		panic(err)
	}
	defer closeExampleInitiator(initiator)

	respCfg := exampleResponderInput("session-1234")
	respCfg.LocalAssociatedData = []byte("server hello")
	responder, msgB, err := cpace.Respond(respCfg, msgA)
	if err != nil {
		panic(err)
	}
	defer closeExampleResponder(responder)

	msgC, initSession, err := initiator.Finish(msgB)
	if err != nil {
		panic(err)
	}
	respSession, err := responder.Finish(msgC)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := initSession.Close(); err != nil {
			panic(err)
		}
	}()
	defer func() {
		if err := respSession.Close(); err != nil {
			panic(err)
		}
	}()

	initKey, _ := initSession.Export([]byte("application key"), nil, 32)
	respKey, _ := respSession.Export([]byte("application key"), nil, 32)
	fmt.Println(bytes.Equal(initKey, respKey))
	fmt.Println(bytes.Equal(initSession.TranscriptID(), respSession.TranscriptID()))
	// Output:
	// true
	// true
}

func ExampleSession_Export() {
	initSession, respSession, err := exampleConfirmedSessions("example-export")
	if err != nil {
		panic(err)
	}
	defer closeExampleSession(initSession)
	defer closeExampleSession(respSession)

	trafficKey, err := initSession.Export([]byte("traffic key"), []byte("initiator to responder"), 32)
	if err != nil {
		panic(err)
	}
	headerKey, err := initSession.Export([]byte("header key"), []byte("initiator to responder"), 32)
	if err != nil {
		panic(err)
	}
	peerTrafficKey, err := respSession.Export([]byte("traffic key"), []byte("initiator to responder"), 32)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(trafficKey))
	fmt.Println(bytes.Equal(trafficKey, headerKey))
	fmt.Println(bytes.Equal(trafficKey, peerTrafficKey))
	// Output:
	// 32
	// false
	// true
}

func ExampleSession_TranscriptID() {
	initSession, respSession, err := exampleConfirmedSessions("example-transcript")
	if err != nil {
		panic(err)
	}
	defer closeExampleSession(initSession)
	defer closeExampleSession(respSession)

	fmt.Println(len(initSession.TranscriptID()))
	fmt.Println(bytes.Equal(initSession.TranscriptID(), respSession.TranscriptID()))
	// Output:
	// 64
	// true
}

func ExampleInitiator_Finish_confirmationFailure() {
	initCfg := exampleInitiatorInput("example-confirmation-failure")
	initCfg.LocalAssociatedData = []byte("client hello")
	initiator, msgA, err := cpace.Start(initCfg)
	if err != nil {
		panic(err)
	}
	defer closeExampleInitiator(initiator)

	respCfg := exampleResponderInput("example-confirmation-failure")
	respCfg.Context = []byte("different protocol context")
	respCfg.LocalAssociatedData = []byte("server hello")
	responder, msgB, err := cpace.Respond(respCfg, msgA)
	if err != nil {
		panic(err)
	}
	defer closeExampleResponder(responder)

	_, _, err = initiator.Finish(msgB)
	fmt.Println(errors.Is(err, cpace.ErrConfirmationFailed))
	// Output:
	// true
}

func ExampleSession_Close() {
	initSession, respSession, err := exampleConfirmedSessions("example-close")
	if err != nil {
		panic(err)
	}
	defer closeExampleSession(respSession)

	if err := initSession.Close(); err != nil {
		panic(err)
	}
	_, err = initSession.Export([]byte("application key"), nil, 32)

	fmt.Println(errors.Is(err, cpace.ErrSessionClosed))
	fmt.Println(len(initSession.TranscriptID()) > 0)
	// Output:
	// true
	// true
}

func exampleInitiatorInput(sessionID string) cpace.Input {
	return cpace.Input{
		Password:  []byte("correct horse battery staple"),
		SelfID:    []byte("client@example"),
		PeerID:    []byte("server@example"),
		Context:   []byte("example protocol v1"),
		SessionID: []byte(sessionID),
	}
}

func exampleResponderInput(sessionID string) cpace.Input {
	return cpace.Input{
		Password:  []byte("correct horse battery staple"),
		SelfID:    []byte("server@example"),
		PeerID:    []byte("client@example"),
		Context:   []byte("example protocol v1"),
		SessionID: []byte(sessionID),
	}
}

func exampleConfirmedSessions(sessionID string) (*cpace.Session, *cpace.Session, error) {
	initCfg := exampleInitiatorInput(sessionID)
	initCfg.LocalAssociatedData = []byte("client hello")
	initiator, msgA, err := cpace.Start(initCfg)
	if err != nil {
		return nil, nil, err
	}
	defer closeExampleInitiator(initiator)

	respCfg := exampleResponderInput(sessionID)
	respCfg.LocalAssociatedData = []byte("server hello")
	responder, msgB, err := cpace.Respond(respCfg, msgA)
	if err != nil {
		return nil, nil, err
	}
	defer closeExampleResponder(responder)

	msgC, initSession, err := initiator.Finish(msgB)
	if err != nil {
		return nil, nil, err
	}
	respSession, err := responder.Finish(msgC)
	if err != nil {
		_ = initSession.Close()
		return nil, nil, err
	}
	return initSession, respSession, nil
}

func closeExampleSession(session *cpace.Session) {
	if err := session.Close(); err != nil {
		panic(err)
	}
}

func closeExampleInitiator(initiator *cpace.Initiator) {
	if err := initiator.Close(); err != nil {
		panic(err)
	}
}

func closeExampleResponder(responder *cpace.Responder) {
	if err := responder.Close(); err != nil {
		panic(err)
	}
}
