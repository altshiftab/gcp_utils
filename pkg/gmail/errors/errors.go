package errors

import "errors"

var (
	ErrNilService                   = errors.New("nil service")
	ErrNilUsersService          = errors.New("nil users service")
	ErrNilUsersMessagesService  = errors.New("nil users messages service")
	ErrNilUsersMessagesSendCall = errors.New("nil users messages send call")
	ErrEmptyFrom = errors.New("empty from")
	ErrEmptyTo = errors.New("empty to")
	ErrEmptySubject = errors.New("empty subject")
	ErrEmptyContentType = errors.New("empty content type")
	ErrBadFromAddress   = errors.New("bad from address")
	ErrEmptyDomain = errors.New("empty domain")
	ErrNilMessage = errors.New("nil message")
)
