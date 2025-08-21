package errors

import "errors"

var (
	ErrNilCredentials = errors.New("nil credentials")
	ErrNilToken       = errors.New("nil token")
	ErrNilTokenSource = errors.New("nil token source")
	ErrEmptyAccountKey              = errors.New("empty account key")
	ErrEmptyImpersonateEmailAddress = errors.New("empty impersonate email address")
	ErrNilAccountKeyConfig          = errors.New("nil account key config")
)
