package cpace

import (
	"crypto/hmac"
	"errors"
	"fmt"
)

type peerShareRole string

const (
	initiatorPeerShare peerShareRole = "initiator"
	responderPeerShare peerShareRole = "responder"
)

var peerShareValidationScalar = []byte{
	0x01, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

func (r peerShareRole) validate(encoded []byte) error {
	_, err := validatePublicShare(encoded)
	if err != nil {
		return r.wrapError(err)
	}
	return nil
}

func (r peerShareRole) sharedSecret(s []byte, encoded []byte) ([]byte, error) {
	k, err := scalarMultVFY(s, encoded)
	if err != nil {
		return nil, r.wrapError(err)
	}
	return k, nil
}

// wrapError applies the ADR-0003 call-site sentinel mapping: the two exported
// peer-share sentinels are rewrapped from the plain sentinel, never from the
// helper's already-ErrAbort-wrapped error, with role context added.
// Non-sentinel defensive errors pass through unchanged.
// A new peer-share sentinel added in validatePublicShare must get a case here,
// or it surfaces without role context.
func (r peerShareRole) wrapError(err error) error {
	switch {
	case errors.Is(err, ErrPeerShareEncoding):
		return fmt.Errorf("%w: invalid %s share: %w", ErrAbort, r, ErrPeerShareEncoding)
	case errors.Is(err, ErrPeerShareIdentity):
		return fmt.Errorf("%w: invalid %s share: %w", ErrAbort, r, ErrPeerShareIdentity)
	default:
		return err
	}
}

func scalarMultVFY(s []byte, encoded []byte) ([]byte, error) {
	if err := validatePublicShareLength(encoded); err != nil {
		return nil, err
	}
	out, err := scalarMult(s, encoded)
	if err != nil {
		return nil, err
	}
	if hmac.Equal(out, identityEncoding) {
		return nil, fmt.Errorf("%w: neutral-element shared secret: %w", ErrAbort, ErrPeerShareIdentity)
	}
	return out, nil
}

func validatePublicShare(encoded []byte) ([]byte, error) {
	if err := validatePublicShareLength(encoded); err != nil {
		return nil, err
	}
	out, err := scalarMultVFY(peerShareValidationScalar, encoded)
	if err != nil {
		return nil, err
	}
	clearBytes(out)
	return clone(encoded), nil
}

func validatePublicShareLength(encoded []byte) error {
	if len(encoded) != pointSize {
		return fmt.Errorf("%w: invalid peer share length", ErrAbort)
	}
	return nil
}
