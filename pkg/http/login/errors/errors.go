package errors

import "errors"

var (
	ErrEmptyUserId                 = errors.New("empty user id")
	ErrEmptyAuthenticationId       = errors.New("empty authentication id")
	ErrEmptySessionCookieName      = errors.New("empty session cookie name")
	ErrEmptySessionCookieDomain    = errors.New("empty session cookie domain")
	ErrNilSessionCookieHeaderEntry = errors.New("nil session cookie header entry")
	ErrEmptyIssuer                 = errors.New("empty issuer")
	ErrEmptyRegisteredDomain       = errors.New("empty registered domain")
	ErrEmptyAllowedAlgs            = errors.New("empty allowed algs")
	ErrNilOriginUrl                = errors.New("nil origin url")
	ErrNilSessionHandler           = errors.New("nil session handler")
	ErrEmptyRegisterPath           = errors.New("empty register path")
	ErrNilDbscConfiguration        = errors.New("nil dbsc configuration")
	ErrNilUserHandler              = errors.New("nil user handler")
	ErrNegativeDuration            = errors.New("negative duration")
	ErrEmptyRefreshPath            = errors.New("empty refresh path")
	ErrEmptyChallenge              = errors.New("empty challenge")
	ErrNoAuthenticationPublicKey   = errors.New("no authentication public key")
)
