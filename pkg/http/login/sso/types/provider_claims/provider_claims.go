package provider_claims

import (
	"fmt"
	"slices"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
)

type ProviderClaims interface {
	VerifiedEmailAddress() (string, error)
	// AuthenticationContext reports how the provider says it authenticated the user. It is nil when
	// the provider said nothing, which is not the same as saying no second factor was used.
	AuthenticationContext() *AuthenticationContext
}

// AuthenticationContext holds what an identity provider states about an authentication event. The
// claims are only present when the provider is asked for them and chooses to supply them.
type AuthenticationContext struct {
	// MethodReferences is the "amr" claim: the methods used, such as pwd, otp, hwk or mfa.
	MethodReferences []string
	// ContextClass is the "acr" claim: the level the authentication reached.
	ContextClass string
	// AuthenticatedAt is the "auth_time" claim: when the user actually authenticated, which may be
	// well before the token was issued if the provider reused an existing session.
	AuthenticatedAt int64
}

// multiFactorMethodReferences are the "amr" values by which a provider states that more than one
// factor was used. Google and Microsoft both use "mfa"; Microsoft also uses "multipleauthn".
var multiFactorMethodReferences = []string{"mfa", "multipleauthn"}

// MultiFactor reports whether the provider stated that more than one factor was used. A nil context,
// or one without method references, reports false: absence of the claim is not evidence that a
// second factor was used, and callers requiring multi-factor should treat it as unproven.
func (c *AuthenticationContext) MultiFactor() bool {
	if c == nil {
		return false
	}

	for _, methodReference := range c.MethodReferences {
		if slices.Contains(multiFactorMethodReferences, strings.ToLower(methodReference)) {
			return true
		}
	}

	return false
}

type GoogleClaims struct {
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Sub           string   `json:"sub"`
	Hd            string   `json:"hd"`
	Amr           []string `json:"amr,omitzero"`
	Acr           string   `json:"acr,omitzero"`
	AuthTime      int64    `json:"auth_time,omitzero"`
}

func (c *GoogleClaims) AuthenticationContext() *AuthenticationContext {
	return &AuthenticationContext{MethodReferences: c.Amr, ContextClass: c.Acr, AuthenticatedAt: c.AuthTime}
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
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Upn               string   `json:"upn"`
	Sub               string   `json:"sub"`
	Tid               string   `json:"tid"`
	Amr               []string `json:"amr,omitzero"`
	Acr               string   `json:"acr,omitzero"`
	AuthTime          int64    `json:"auth_time,omitzero"`
}

func (c *MicrosoftClaims) AuthenticationContext() *AuthenticationContext {
	return &AuthenticationContext{MethodReferences: c.Amr, ContextClass: c.Acr, AuthenticatedAt: c.AuthTime}
}

func (c *MicrosoftClaims) VerifiedEmailAddress() (string, error) {
	if c.Email == "" {
		return "", motmedelErrors.NewWithTrace(
			fmt.Errorf("%w (email address is empty)", ssoErrors.ErrForbiddenUser),
		)
	}

	return c.Email, nil
}
