package errors

import "errors"

var (
	ErrSessionIdMismatch = errors.New("session id mismatch")
	ErrPublicKeyMismatch = errors.New("public key mismatch")
)
