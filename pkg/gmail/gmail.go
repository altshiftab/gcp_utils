package gmail

import (
	"context"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	gcpUtilsAuth "github.com/altshiftab/gcp_utils/pkg/auth"
	gcpUtilsAuthErrors "github.com/altshiftab/gcp_utils/pkg/auth/errors"
	gmailUtilsErrors "github.com/altshiftab/gcp_utils/pkg/gmail/errors"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

func MakeGmailUsersMessagesService(
	ctx context.Context,
	accountKey []byte,
	impersonateEmailAddress string,
) (*gmail.UsersMessagesService, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(accountKey) == 0 {
		return nil, nil
	}

	if impersonateEmailAddress == "" {
		return nil, motmedelErrors.NewWithTrace(gcpUtilsAuthErrors.ErrEmptyImpersonateEmailAddress)
	}

	httpClient, err := gcpUtilsAuth.MakeImpersonatedOauthClientFromAccountKey(
		ctx,
		accountKey,
		impersonateEmailAddress,
		gmail.GmailSendScope,
	)
	if err != nil {
		return nil, fmt.Errorf("make impersonated oauth client from account key: %w", err)
	}
	if httpClient == nil {
		return nil, motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpClient)
	}

	gmailService, err := gmail.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("gmail new service: %w", err), httpClient)
	}
	if gmailService == nil {
		return nil, motmedelErrors.NewWithTrace(gmailUtilsErrors.ErrNilGmailService)
	}

	gmailUsersService := gmailService.Users
	if gmailUsersService == nil {
		return nil, motmedelErrors.NewWithTrace(gmailUtilsErrors.ErrNilGmailUsersService)
	}

	return gmailUsersService.Messages, nil
}
