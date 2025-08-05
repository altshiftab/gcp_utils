package errors

import "errors"

var (
	ErrNilGmailService      = errors.New("nil gmail service")
	ErrNilGmailUsersService = errors.New("nil gmail users service")
	ErrNilGmailUsersMessagesService = errors.New("nil gmail users messages service")
)
