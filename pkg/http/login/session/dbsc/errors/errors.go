package errors

import "errors"

var (
	ErrSessionIdMismatch     = errors.New("session id mismatch")
	ErrPublicKeyMismatch     = errors.New("public key mismatch")
	ErrEmptyAudience         = errors.New("empty audience")
	ErrNilInput              = errors.New("nil input")
	ErrEmptyTokenString      = errors.New("empty token string")
	ErrEmptyAuthenticationId = errors.New("empty authentication id")
	ErrNilCheckChallenge     = errors.New("nil check challenge")
)
