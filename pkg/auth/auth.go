package auth

import (
	"context"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	gcpUtilsAuthErrors "github.com/altshiftab/gcp_utils/pkg/auth/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const defaultCredentialsScope = "https://www.googleapis.com/auth/cloud-platform"

func GetDefaultCredentialsTokenWithScope(scope string) (*oauth2.Token, error) {
	credentials, err := google.FindDefaultCredentials(context.Background(), scope)
	if err != nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(
			fmt.Errorf("find default credentials: %w", err),
			scope,
		)
	}
	if credentials == nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(gcpUtilsAuthErrors.ErrNilCredentials)
	}

	credentialsToken, err := credentials.TokenSource.Token()
	if err != nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(fmt.Errorf("token source token: %w", err))
	}

	return credentialsToken, nil
}

func GetDefaultCredentialsToken() (*oauth2.Token, error) {
	return GetDefaultCredentialsTokenWithScope(defaultCredentialsScope)
}
