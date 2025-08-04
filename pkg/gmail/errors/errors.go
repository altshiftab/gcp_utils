package errors

import "errors"

var (
	ErrNilGmailService      = errors.New("nil gmail service")
	ErrNilGmailUsersService = errors.New("nil gmail users service")
)
