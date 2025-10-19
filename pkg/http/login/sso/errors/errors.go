package errors

import "errors"

var (
	ErrNilOauth2Configuration = errors.New("nil oauth2 configuration")
	ErrNilOauth2Token = errors.New("nil oauth2 token")
	ErrNilTokenVerifier = errors.New("nil token verifier")
	ErrUnverifiedEmail = errors.New("unverified email")
)

