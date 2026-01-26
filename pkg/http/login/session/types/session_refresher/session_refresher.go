package session_refresher

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/utils"
	errors2 "github.com/altshiftab/gcp_utils/pkg/http/login/session/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/database/authentication"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_cookie"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_refresher/session_refresher_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
)

type Refresher struct {
	Signer       motmedelCryptoInterfaces.NamedSigner
	CookieDomain string
	*session_refresher_config.Config
}

func (r *Refresher) Refresh(
	authentication *authentication.Authentication,
	sessionToken *session_token.Token,
	authenticationMethod string,
	sessionDuration time.Duration,
) (*response.Response, *response_error.ResponseError) {
	if authentication == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authentication")),
		}
	}

	if sessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session token")),
		}
	}

	if authenticationMethod == "" {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication method")),
		}
	}

	signer := r.Signer
	if utils.IsNil(signer) {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("signer")),
		}
	}

	newSessionToken, err := sessionToken.Refresh(authentication, sessionDuration, authenticationMethod)
	if err != nil {
		if errors.Is(err, errors2.ErrEndedAuthentication) {
			return nil, &response_error.ResponseError{
				Headers: []*response.HeaderEntry{{Name: "Clear-Site-Data", Value: `"cookies"`}},
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session's authentication has ended."),
				),
			}
		} else if errors.Is(err, errors2.ErrExpiredAuthentication) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session's authentication has expired."),
				),
			}
		}

		return nil, &response_error.ResponseError{ServerError: fmt.Errorf("session token refresh: %w", err)}
	}
	if newSessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("new session token")),
		}
	}

	newSessionTokenClaims := newSessionToken.Claims
	if newSessionTokenClaims == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("new session token claims")),
		}
	}
	newSessionTokenExpiresAt := newSessionTokenClaims.ExpiresAt
	if newSessionTokenExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("new session token claims expires at")),
		}
	}

	newSessionTokenString, err := newSessionToken.Encode(signer)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(
				fmt.Errorf("new session token encode: %w", err),
				newSessionToken, signer,
			),
		}
	}

	sessionCookie, err := session_cookie.New(
		newSessionTokenString,
		newSessionTokenExpiresAt.Time,
		r.CookieName,
		r.CookieDomain,
	)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(
				fmt.Errorf("session cookie new: %w", err),
				newSessionTokenString, newSessionTokenExpiresAt.Time, r.CookieName, r.CookieDomain,
			),
		}
	}
	if sessionCookie == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session cookie")),
		}
	}

	return &response.Response{
		Headers: []*response.HeaderEntry{{Name: "Set-Cookie", Value: sessionCookie.String()}},
	}, nil
}

func New(
	signer motmedelCryptoInterfaces.NamedSigner,
	cookieDomain string,
	options ...session_refresher_config.Option,
) (*Refresher, error) {
	if utils.IsNil(signer) {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("signer"))
	}

	if cookieDomain == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("cookie domain"))
	}

	config := session_refresher_config.New(options...)

	return &Refresher{Signer: signer, CookieDomain: cookieDomain, Config: config}, nil
}
