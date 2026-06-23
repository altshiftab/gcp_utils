package oauth_error

import "fmt"

// Error represents an OAuth 2.0 authorization error response (RFC 6749 §4.1.2.1),
// which the provider returns via the redirect URI instead of an authorization
// code, e.g. when the user declines consent or cancels (error=access_denied).
type Error struct {
	// Code is the OAuth 2.0 `error` parameter, e.g. "access_denied".
	Code string
	// Subcode is a provider extension (Microsoft `error_subcode`, e.g. "cancel").
	Subcode string
	// Description is the human-readable `error_description` parameter.
	Description string
	// Uri is the `error_uri` parameter.
	Uri string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("oauth error: %s", e.Code)
	if e.Subcode != "" {
		msg += fmt.Sprintf(" (%s)", e.Subcode)
	}
	if e.Description != "" {
		msg += fmt.Sprintf(": %s", e.Description)
	}

	return msg
}

// GetCode satisfies github.com/Motmedel/utils_go/pkg/errors.CodeErrorI so the
// OAuth error code is emitted as ECS `error.code` by the error context extractor.
func (e *Error) GetCode() string {
	return e.Code
}

func New(code, subcode, description, uri string) *Error {
	return &Error{Code: code, Subcode: subcode, Description: description, Uri: uri}
}
