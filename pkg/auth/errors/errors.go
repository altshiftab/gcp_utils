package errors

import "errors"

var (
	ErrNilCredentials = errors.New("nil credentials")
	ErrNilToken       = errors.New("nil token")
)
