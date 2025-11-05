package errors

import "errors"

var (
	ErrNotStruct           = errors.New("not a struct")
	ErrInputOutputNotFound = errors.New("input or output not found")
	ErrUseEncryptionWithEmptyServerJwk = errors.New("use encryption with empty server jwk")
)
