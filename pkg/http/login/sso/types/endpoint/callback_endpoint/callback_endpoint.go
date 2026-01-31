package callback_endpoint

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	motmedelDatabase "github.com/Motmedel/utils_go/pkg/database"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	motmedelJwt "github.com/Motmedel/utils_go/pkg/json/jose/jwt"
	authenticatorPkg "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/oauth_flow"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/provider_claims"
	"golang.org/x/oauth2"
)

type UrlInput struct {
	State        string `json:"state"`
	Code         string `json:"code"`
	Scope        string `json:"scope,omitempty"`
	AuthUser     int    `json:"authuser,omitempty"`
	HostedDomain string `json:"hd,omitempty"`
	Prompt       string `json:"prompt,omitempty"`
	SessionState string `json:"session_state,omitempty"`
}

var urlInputParser = query_extractor.New[*UrlInput]()

type Endpoint[T provider_claims.ProviderClaims] struct {
	*initialization_endpoint.Endpoint
	CallbackCookieName    string
	DbscChallengeDuration time.Duration
	popOauthFlow          func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error)
}

func (e *Endpoint[T]) Initialize(
	oauthConfig *oauth2.Config,
	idTokenAuthenticator *authenticatorPkg.AuthenticatorWithKeyHandler,
	sessionManager *session_manager.Manager,
) error {
	if oauthConfig == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("oauth config"))
	}

	if idTokenAuthenticator == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("id token authenticator"))
	}

	if sessionManager == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager"))
	}

	db := sessionManager.Db
	if db == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager sql db"))
	}

	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		urlInput, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*UrlInput](ctx)
		if responseError != nil {
			return nil, responseError
		}

		callbackCookie, err := request.Cookie(e.CallbackCookieName)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				return nil, &response_error.ResponseError{
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("No callback cookie."),
					),
				}
			}
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("request cookie: %w", err), e.CallbackCookieName),
			}
		}
		if callbackCookie == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("%w (callback)", motmedelHttpErrors.ErrNilCookie)),
			}
		}

		oauthFlowId := callbackCookie.Value
		if oauthFlowId == "" {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(empty_error.New("callback cookie value")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Empty callback cookie."),
				),
			}
		}

		dbPopCtx, dbPopCtxCancel := motmedelDatabase.MakeTimeoutCtx(ctx)
		defer dbPopCtxCancel()

		oauthFlow, err := e.popOauthFlow(dbPopCtx, oauthFlowId, db)
		if err != nil {
			wrappedErr := motmedelErrors.New(fmt.Errorf("get oauth flow: %w", err), oauthFlowId)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("No OAuth flow matches the callback cookie value."),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if oauthFlow == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(nil_error.New("oauth flow")),
			}
		}

		oauthFlowExpiresAt := oauthFlow.ExpiresAt
		if oauthFlowExpiresAt == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("oauth flow expires at")),
			}
		}

		if oauthFlowExpiresAt.Before(time.Now()) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The OAuth flow has expired."),
				),
			}
		}

		if oauthFlow.State != urlInput.State {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The OAuth flow state and url state do not match."),
				),
			}
		}

		token, err := oauthConfig.Exchange(ctx, urlInput.Code, oauth2.VerifierOption(oauthFlow.CodeVerifier))
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("oauth config exchange: %w", err)),
			}
		}
		if token == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("oauth token")),
			}
		}

		idTokenAny := token.Extra("id_token")
		idToken, err := utils.ConvertToNonZero[string](idTokenAny)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(fmt.Errorf("convert to non zero (id token): %w", err), idTokenAny),
			}
		}

		authenticatedIdToken, err := idTokenAuthenticator.Authenticate(ctx, idToken)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(
					fmt.Errorf("authenticator with key handler authenticate: %w", err),
					idToken,
				),
			}
		}
		if authenticatedIdToken == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("authenticated id token")),
			}
		}

		_, idTokenPayload, _, err := motmedelJwt.Parse(idToken)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("jwt parse: %w", err), idToken),
			}
		}
		if len(idTokenPayload) == 0 {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("id token payload")),
			}
		}

		var providerClaims T
		if err := json.Unmarshal(idTokenPayload, &providerClaims); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(
					fmt.Errorf("json unmarshal (authenticated id token raw): %w", err),
					idTokenPayload,
				),
			}
		}

		emailAddress, err := providerClaims.VerifiedEmailAddress()
		if err != nil {
			wrappedErr := motmedelErrors.New(
				fmt.Errorf("provider claims verified email address: %w", err),
				providerClaims,
			)
			if errors.Is(err, ssoErrors.ErrForbiddenUser) {
				return nil, &response_error.ResponseError{
					ProblemDetail: problem_detail.New(
						http.StatusForbidden,
						problem_detail_config.WithDetail("The email address that is tied to the id token is unverified or invalid."),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if emailAddress == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("email address")),
			}
		}

		response, responseError := sessionManager.CreateSession(ctx, emailAddress)
		if responseError != nil {
			return nil, responseError
		}
		if response == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("response")),
			}
		}

		response.StatusCode = http.StatusSeeOther

		clearedCallbackCookie := http.Cookie{
			Name:     e.CallbackCookieName,
			Path:     e.Path,
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		response.Headers = append(
			response.Headers,
			&muxResponse.HeaderEntry{
				Name:  "Location",
				Value: oauthFlow.RedirectUrl,
			},
			&muxResponse.HeaderEntry{
				Name:  "Set-Cookie",
				Value: clearedCallbackCookie.String(),
			},
		)

		return response, nil
	}

	e.Initialized = true

	return nil
}

func New[T provider_claims.ProviderClaims](path string, options ...callback_endpoint_config.Option) (*Endpoint[T], error) {
	if path == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("path"))
	}

	config := callback_endpoint_config.New(options...)
	return &Endpoint[T]{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      path,
				Method:    http.MethodGet,
				UrlParser: adapter.New(urlInputParser),
				Public:    true,
				Hint: &endpoint.Hint{
					InputType: motmedelReflect.TypeOf[UrlInput](),
				},
			},
		},
		CallbackCookieName: config.CallbackCookieName,
		popOauthFlow:       config.PopOauthFlow,
	}, nil
}
