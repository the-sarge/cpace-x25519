package cpace

import (
	"testing"
)

// The secret snapshots below are the only place hygiene tests may learn the
// cores' field layout. Snapshot before the terminal operation (the aliases
// must be captured while the secrets are still live), then assertCleared
// after it.

type initiatorSecretSnapshot struct {
	tb        testing.TB
	initiator *Initiator
	scalar    []byte
}

func snapshotInitiatorSecrets(tb testing.TB, i *Initiator) initiatorSecretSnapshot {
	tb.Helper()
	scalar := i.state.core.scalar
	if scalar == nil {
		tb.Fatal("snapshot taken after initiator scalar was already cleared")
	}
	return initiatorSecretSnapshot{tb: tb, initiator: i, scalar: scalar}
}

func (s initiatorSecretSnapshot) assertCleared() {
	s.tb.Helper()
	if s.initiator.state.core.scalar != nil {
		s.tb.Fatal("initiator core retained scalar reference after terminal operation")
	}
	if !allZero(s.scalar) {
		s.tb.Fatal("initiator scalar backing array was not cleared")
	}
}

type responderSecretSnapshot struct {
	tb         testing.TB
	responder  *Responder
	isk        []byte
	transcript [][]byte
}

func snapshotResponderSecrets(tb testing.TB, r *Responder) responderSecretSnapshot {
	tb.Helper()
	core := r.state.core
	if core.isk == nil {
		tb.Fatal("snapshot taken after responder ISK was already cleared")
	}
	tr := &core.transcript
	return responderSecretSnapshot{
		tb:         tb,
		responder:  r,
		isk:        core.isk,
		transcript: [][]byte{tr.transcript, tr.ya, tr.ada, tr.yb, tr.adb},
	}
}

func (s responderSecretSnapshot) assertCleared() {
	s.tb.Helper()
	core := s.responder.state.core
	if core.isk != nil {
		s.tb.Fatal("responder core retained ISK reference after terminal operation")
	}
	tr := &core.transcript
	if tr.transcript != nil || tr.ya != nil || tr.ada != nil || tr.yb != nil || tr.adb != nil {
		s.tb.Fatal("responder core retained transcript references after terminal operation")
	}
	if !allZero(s.isk) {
		s.tb.Fatal("responder-owned ISK backing array was not cleared")
	}
	for _, b := range s.transcript {
		if !allZero(b) {
			s.tb.Fatal("responder-owned transcript backing array was not cleared")
		}
	}
}
