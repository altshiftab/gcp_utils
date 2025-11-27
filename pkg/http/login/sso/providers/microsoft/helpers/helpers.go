package helpers

import (
	"context"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	ssoHelpers "github.com/altshiftab/gcp_utils/pkg/http/login/sso"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
	microsoftTypes "github.com/altshiftab/gcp_utils/pkg/http/login/sso/providers/microsoft/types"
	"github.com/coreos/go-oidc"
)

func HandleMicrosoftToken(ctx context.Context, idTokenString string, verifier *oidc.IDTokenVerifier) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context error: %w", err)
	}

	if verifier == nil {
		return "", motmedelErrors.NewWithTrace(ssoErrors.ErrNilTokenVerifier)
	}

	if idTokenString == "" {
		return "", nil
	}

	idToken, err := verifier.Verify(ctx, idTokenString)
	if err != nil {
		return "", motmedelErrors.NewWithTrace(
			fmt.Errorf("token verifier verify: %w: %w", motmedelErrors.ErrValidationError, err),
		)
	}
	if idToken == nil {
		return "", motmedelErrors.NewWithTrace(ssoHelpers.ErrNilIdToken)
	}

	var claims microsoftTypes.MicrosoftClaims
	if err = idToken.Claims(&claims); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("id token claims: %w", err), idToken)
	}

	emailAddress := claims.Email
	if emailAddress == "" {
		return "", fmt.Errorf("%w: %w", motmedelErrors.ErrValidationError, ssoErrors.ErrEmptyEmailAddress)
	}

	return emailAddress, nil
}
