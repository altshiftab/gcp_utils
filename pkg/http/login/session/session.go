package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/Motmedel/utils_go/pkg/errors"
)

func GenerateDbscChallenge() (string, error) {
	challenge := make([]byte, 64)
	if _, err := rand.Read(challenge); err != nil {
		return "", errors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return base64.URLEncoding.EncodeToString(challenge), nil
}
