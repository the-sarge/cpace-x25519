package cpace

import "fmt"

const (
	maxPasswordLength       = 4 << 10
	maxIDLength             = 4 << 10
	maxContextLength        = 1 << 10
	maxSessionIDLength      = 1 << 10
	maxAssociatedDataLength = 64 << 10
)

type packageCapField struct {
	name   string
	length int
	exact  bool
}

func cappedPackageCapField(name string, maxLen int) packageCapField {
	return packageCapField{name: name, length: maxLen}
}

func exactPackageCapField(name string, wantLen int) packageCapField {
	return packageCapField{name: name, length: wantLen, exact: true}
}

type acceptedInput struct {
	password []byte
	selfID   []byte
	peerID   []byte
	context  []byte
	sid      []byte
	localAD  []byte
}

func acceptInput(input Input) (acceptedInput, error) {
	if len(input.Password) == 0 {
		return acceptedInput{}, fmt.Errorf("%w: empty password", ErrInvalidInput)
	}
	if len(input.SelfID) == 0 {
		return acceptedInput{}, fmt.Errorf("%w: empty self id", ErrInvalidInput)
	}
	if len(input.PeerID) == 0 {
		return acceptedInput{}, fmt.Errorf("%w: empty peer id", ErrInvalidInput)
	}
	if len(input.SessionID) == 0 && !input.AllowEmptySessionID {
		return acceptedInput{}, fmt.Errorf("%w: %w", ErrInvalidInput, ErrEmptySessionID)
	}

	for _, field := range []struct {
		cap   packageCapField
		value []byte
	}{
		{passwordCap, input.Password},
		{selfIDCap, input.SelfID},
		{peerIDCap, input.PeerID},
		{contextCap, input.Context},
		{sessionIDCap, input.SessionID},
		{localAssociatedDataCap, input.LocalAssociatedData},
	} {
		if err := field.cap.validateInputLength(len(field.value)); err != nil {
			return acceptedInput{}, err
		}
	}

	return acceptedInput{
		password: clone(input.Password),
		selfID:   clone(input.SelfID),
		peerID:   clone(input.PeerID),
		context:  clone(input.Context),
		sid:      clone(input.SessionID),
		localAD:  clone(input.LocalAssociatedData),
	}, nil
}

func (c *acceptedInput) wipe() {
	if c == nil {
		return
	}
	clearBytes(c.password)
	clearBytes(c.selfID)
	clearBytes(c.peerID)
	clearBytes(c.context)
	clearBytes(c.sid)
	clearBytes(c.localAD)
}

func (f packageCapField) validateInputLength(n int) error {
	if n > f.length {
		return fmt.Errorf("%w: %s too large", ErrInvalidInput, f.name)
	}
	return nil
}

func (f packageCapField) acceptMessageField(buf []byte, off, n int) ([]byte, int, error) {
	if err := f.validateMessageLength(n); err != nil {
		return nil, off, err
	}
	if len(buf)-off < n {
		return nil, off, fmt.Errorf("%w: truncated %s field", ErrMessage, f.name)
	}
	out := clone(buf[off : off+n])
	return out, off + n, nil
}

func (f packageCapField) validateMessageLength(n int) error {
	if f.exact {
		if n != f.length {
			return fmt.Errorf("%w: %s length", ErrMessage, f.name)
		}
	} else if n > f.length {
		return fmt.Errorf("%w: %s field too large", ErrMessage, f.name)
	}
	return nil
}

func shippedPackageCapPolicy() []packageCapField {
	return []packageCapField{
		passwordCap,
		selfIDCap,
		peerIDCap,
		contextCap,
		sessionIDCap,
		localAssociatedDataCap,
		messageASessionIDCap,
		messageAPointCap,
		messageAAssociatedDataCap,
		messageBPointCap,
		messageBAssociatedDataCap,
		messageBTagCap,
		messageCTagCap,
	}
}

var (
	passwordCap            = cappedPackageCapField("password", maxPasswordLength)
	selfIDCap              = cappedPackageCapField("self id", maxIDLength)
	peerIDCap              = cappedPackageCapField("peer id", maxIDLength)
	contextCap             = cappedPackageCapField("context", maxContextLength)
	sessionIDCap           = cappedPackageCapField("session id", maxSessionIDLength)
	localAssociatedDataCap = cappedPackageCapField("local associated data", maxAssociatedDataLength)

	messageASessionIDCap      = cappedPackageCapField("message A session id", maxSessionIDLength)
	messageAPointCap          = exactPackageCapField("message A point", pointSize)
	messageAAssociatedDataCap = cappedPackageCapField("message A associated data", maxAssociatedDataLength)
	messageBPointCap          = exactPackageCapField("message B point", pointSize)
	messageBAssociatedDataCap = cappedPackageCapField("message B associated data", maxAssociatedDataLength)
	messageBTagCap            = exactPackageCapField("message B tag", tagSize)
	messageCTagCap            = exactPackageCapField("message C tag", tagSize)
)
