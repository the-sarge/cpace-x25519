package cpace

import (
	"crypto/hkdf"
	"crypto/sha512"
	"fmt"
)

const maxHKDFOutput = 255 * 64

// TranscriptID returns the draft CPaceSidOutput value for the confirmed
// initiator-responder CPace transcript. It is not a complete channel binding
// for any outer version, suite, or application-protocol negotiation.
func (s *Session) TranscriptID() []byte {
	if s == nil {
		return nil
	}
	return clone(s.transcriptID)
}

// Export derives deterministic application key material from the confirmed ISK
// using HKDF-SHA512. The label and context are prefix-free encoded into HKDF
// info. Export output is not fresh randomness or a randomness pool; use
// separate, domain-specific labels and contexts for each application purpose.
func (s *Session) Export(label, context []byte, length int) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil session", ErrInvalidInput)
	}
	if length < 0 || length > maxHKDFOutput {
		return nil, fmt.Errorf("%w: invalid export length", ErrInvalidInput)
	}
	info := lvCat([]byte("CPaceExport"), label, context)
	out, err := hkdf.Key(sha512.New, s.isk, nil, string(info), length)
	if err != nil {
		return nil, fmt.Errorf("%w: export failed: %v", ErrInvalidInput, err)
	}
	return out, nil
}
