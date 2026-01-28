package provider_claims

import (
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
)

type ProviderClaims interface {
	VerifiedEmailAddress() (string, error)
}

type GoogleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
	Hd            string `json:"hd"`
}

func (c *GoogleClaims) VerifiedEmailAddress() (string, error) {
	if c.Email == "" {
		return "", motmedelErrors.NewWithTrace(
			fmt.Errorf("%w (email address is empty)", ssoErrors.ErrForbiddenUser),
		)
	}

	if !c.EmailVerified {
		return "", motmedelErrors.NewWithTrace(
			fmt.Errorf("%w (email address not verified)", ssoErrors.ErrForbiddenUser),
		)
	}

	return c.Email, nil
}

type MicrosoftClaims struct {
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Upn               string `json:"upn"`
	Sub               string `json:"sub"`
	Tid               string `json:"tid"`
}

func (c *MicrosoftClaims) VerifiedEmailAddress() (string, error) {
	if c.Email == "" {
		return "", motmedelErrors.NewWithTrace(
			fmt.Errorf("%w (email address is empty)", ssoErrors.ErrForbiddenUser),
		)
	}

	return c.Email, nil
}
