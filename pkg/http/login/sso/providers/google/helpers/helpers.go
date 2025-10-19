package helpers

import (
	"context"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	ssoHelpers "github.com/altshiftab/gcp_utils/pkg/http/login/sso"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
	googleProviderTypes "github.com/altshiftab/gcp_utils/pkg/http/login/sso/providers/google/types"
	"github.com/coreos/go-oidc"
)

func HandleGoogleToken(ctx context.Context, accessToken string, verifier *oidc.IDTokenVerifier) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context error: %w", err)
	}

	if accessToken == "" {
		return "", nil
	}

	if verifier == nil {
		return "", motmedelErrors.NewWithTrace(ssoErrors.ErrNilTokenVerifier)
	}

	idToken, err := verifier.Verify(ctx, accessToken)
	if err != nil {
		return "", motmedelErrors.NewWithTrace(
			fmt.Errorf("token verifier verify: %w: %w", motmedelErrors.ErrValidationError, err),
		)
	}
	if idToken == nil {
		return "", motmedelErrors.NewWithTrace(ssoHelpers.ErrNilIdToken)
	}

	var claims googleProviderTypes.GoogleClaims
	if err = idToken.Claims(&claims); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("id token claims: %w", err), idToken)
	}

	// TODO: Check more?

	if !claims.EmailVerified {
		return "", fmt.Errorf("%w: %w", motmedelErrors.ErrValidationError, ssoErrors.ErrUnverifiedEmail)
	}

	return claims.Email, nil
}
