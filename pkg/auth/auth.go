package auth

import (
	"context"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	authErrors "github.com/altshiftab/gcp_utils/pkg/auth/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"net/http"
)

const defaultCredentialsScope = "https://www.googleapis.com/auth/cloud-platform"

func GetDefaultCredentialsToken(ctx context.Context, scopes ...string) (*oauth2.Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, motmedelErrors.NewWithTrace(err, ctx)
	}

	if len(scopes) == 0 {
		scopes = []string{defaultCredentialsScope}
	}

	credentials, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("find default credentials: %w", err))
	}
	if credentials == nil {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrNilCredentials)
	}

	// TODO: Can I check if this interface is nil?
	credentialsToken, err := credentials.TokenSource.Token()
	if err != nil {
		return nil, motmedelErrors.New(fmt.Errorf("token source token: %w", err))
	}

	return credentialsToken, nil
}

func makeOauthClient(
	ctx context.Context,
	accountKey []byte,
	impersonateEmailAddress string,
	scopes ...string,
) (*http.Client, error) {
	if len(accountKey) == 0 {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrEmptyAccountKey)
	}

	if err := ctx.Err(); err != nil {
		return nil, motmedelErrors.NewWithTrace(err, ctx)
	}

	accountKeyConfig, err := google.JWTConfigFromJSON(accountKey, scopes...)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("google jwt config from json: %w", err))
	}
	if accountKeyConfig == nil {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrNilAccountKeyConfig)
	}

	accountKeyConfig.Subject = impersonateEmailAddress

	// TODO: Can I check if this interface is nil?
	accountKeyToken, err := accountKeyConfig.TokenSource(ctx).Token()
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("jwt config token source: %w", err))
	}

	return oauth2.NewClient(ctx, oauth2.StaticTokenSource(accountKeyToken)), nil
}

func MakeOauthClientFromAccountKey(ctx context.Context, accountKey []byte, scopes ...string) (*http.Client, error) {
	if len(accountKey) == 0 {
		return nil, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, motmedelErrors.NewWithTrace(err, ctx)
	}

	return makeOauthClient(ctx, accountKey, "", scopes...)
}

func MakeImpersonatedOauthClientFromAccountKey(
	ctx context.Context,
	accountKey []byte,
	impersonateEmailAddress string,
	scopes ...string,
) (*http.Client, error) {
	if len(accountKey) == 0 {
		return nil, nil
	}

	if impersonateEmailAddress == "" {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrEmptyImpersonateEmailAddress)
	}

	if err := ctx.Err(); err != nil {
		return nil, motmedelErrors.NewWithTrace(err, ctx)
	}

	return makeOauthClient(ctx, accountKey, impersonateEmailAddress, scopes...)
}
