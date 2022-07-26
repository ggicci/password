package password

import (
	"errors"
)

var (
	ErrMissmatchedPassword    = errors.New("mismatched password")
	ErrMalformedPassword      = errors.New("malformed password")
	ErrNotArgon2idPassword    = errors.New("not an argon2id password")
	ErrUnsupportedAlgoVersion = errors.New("unsupported algorithm version")
)
