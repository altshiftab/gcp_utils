package sso

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
)

var (
	ErrNilIdToken = errors.New("nil id token")
)

func MakeCodeVerifier() (string, error) {
	challenge := make([]byte, 96)
	if _, err := rand.Read(challenge); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return base64.RawURLEncoding.EncodeToString(challenge), nil
}
