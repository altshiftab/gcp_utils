package auth

import (
	"context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	gcpUtilsAuthErrors "github.com/altshiftab/gcp_utils/pkg/auth/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const defaultCredentialsScope = "https://www.googleapis.com/auth/cloud-platform"

func GetDefaultCredentialsTokenWithScope(scope string) (*oauth2.Token, error) {
	credentials, err := google.FindDefaultCredentials(context.Background(), scope)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when obtaining default credentials.",
			Cause:   err,
			Input:   scope,
		}
	}
	if credentials == nil {
		return nil, gcpUtilsAuthErrors.ErrNilCredentials
	}

	credentialsToken, err := credentials.TokenSource.Token()
	if err != nil {
		return nil, &motmedelErrors.CauseError{
			Message: "An error occurred when obtaining a token from the token source.",
			Cause:   err,
		}
	}

	return credentialsToken, nil
}

func GetDefaultCredentialsToken() (*oauth2.Token, error) {
	return GetDefaultCredentialsTokenWithScope(defaultCredentialsScope)
}
