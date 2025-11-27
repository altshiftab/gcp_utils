package errors

import "errors"

var (
	ErrNilOauth2Configuration = errors.New("nil oauth2 configuration")
	ErrNilOauth2Token = errors.New("nil oauth2 token")
	ErrNilTokenVerifier = errors.New("nil token verifier")
	ErrUnverifiedEmail = errors.New("unverified email")
	ErrNilCseConfig = errors.New("nil cse config")
	ErrEmptyCodeVerifier = errors.New("empty code verifier")
	ErrEmptyCode         = errors.New("empty code")
	ErrEmptyEmailAddress = errors.New("empty email address")
	ErrEmptySessionToken = errors.New("empty session token")
	ErrNilOauthFlow = errors.New("nil oauth flow")
	ErrForbiddenUser = errors.New("forbidden user")
	ErrNilJwe = errors.New("nil jwe")
)

