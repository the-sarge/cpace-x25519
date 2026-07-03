package cpace

import "errors"

var (
	// ErrInvalidInput reports invalid local configuration or parameters.
	ErrInvalidInput = errors.New("cpace: invalid input")

	// ErrEmptySessionID reports an empty Input.SessionID without the explicit
	// AllowEmptySessionID compatibility opt-in. The returned error also wraps
	// ErrInvalidInput.
	ErrEmptySessionID = errors.New("cpace: empty session id")

	// ErrRandomness reports randomness-related failures.
	ErrRandomness = errors.New("cpace: randomness failure")

	// ErrMessage reports malformed or unexpected wire messages.
	ErrMessage = errors.New("cpace: invalid message")

	// ErrStateUsed reports an attempt to reuse a single-use protocol state.
	ErrStateUsed = errors.New("cpace: state already used")

	// ErrSessionClosed reports an attempt to export key material from a closed
	// Session.
	ErrSessionClosed = errors.New("cpace: session closed")

	// ErrAbort reports a draft abort condition such as an invalid point or
	// neutral-element Diffie-Hellman result.
	ErrAbort = errors.New("cpace: protocol abort")

	// ErrPeerShareEncoding reports a peer public share encoding error. Public
	// message framing catches malformed X25519 share lengths before peer-share
	// validation.
	ErrPeerShareEncoding = errors.New("cpace: peer share encoding")

	// ErrPeerShareIdentity reports a peer public share that maps to the
	// X25519 neutral shared-secret output. The returned error also wraps
	// ErrAbort.
	ErrPeerShareIdentity = errors.New("cpace: peer share identity")

	// ErrConfirmationFailed reports failed explicit key confirmation.
	ErrConfirmationFailed = errors.New("cpace: key confirmation failed")
)
