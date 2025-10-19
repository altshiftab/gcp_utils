package errors

import "errors"

var (
	ErrNilSigningData             = errors.New("nil signing data")
	ErrEmailAddressUserIdConflict = errors.New("email address user id conflict")
	ErrNilValidationResponseError = errors.New("nil validation response error")
	ErrUnexpectedAlgorithm = errors.New("unexpected algorithm")
	ErrNoPublicKeyCredential = errors.New("no public key credential")
)
