package errors

import "errors"

var (
	ErrNilService                   = errors.New("nil service")
	ErrNilUsersService          = errors.New("nil users service")
	ErrNilUsersMessagesService  = errors.New("nil users messages service")
	ErrNilUsersMessagesSendCall = errors.New("nil users messages send call")
)
