package helpers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
)

func GenerateChallenge() (string, error) {
	challenge := make([]byte, 64)
	if _, err := rand.Read(challenge); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return base64.URLEncoding.EncodeToString(challenge), nil
}
