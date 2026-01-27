package callback_endpoint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

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
	authenticatorPkg "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token/authenticated_token"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/session/types/database/authentication"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/database/oauth_flow"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
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

type Endpoint struct {
	*initialization_endpoint.Endpoint
	CallbackCookieName string
}

func (e *Endpoint) Initialize(
	oauthConfig *oauth2.Config,
	getOauthFlow func(ctx context.Context, id string) (*oauth_flow.Flow, error),
	idTokenAuthenticator *authenticatorPkg.AuthenticatorWithKeyHandler,
	handleAuthenticatedIdToken func(context.Context, *authenticated_token.Token) (*authenticationPkg.Authentication, error),
	insertDbscChallenge func(ctx context.Context, challenge string, authenticationId string) error,
	sessionManager *session_manager.Manager,
) error {
	if oauthConfig == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("oauth config"))
	}

	if getOauthFlow == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("get oauth flow"))
	}

	if idTokenAuthenticator == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("id token authenticator"))
	}

	if handleAuthenticatedIdToken == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("handle authenticated id token"))
	}

	if insertDbscChallenge == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("insert dbsc challenge"))
	}

	if sessionManager == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager"))
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
		oauthFlow, err := getOauthFlow(ctx, oauthFlowId)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(fmt.Errorf("get oauth flow: %w", err), oauthFlowId),
			}
		}
		if oauthFlow == nil {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("No OAuth flow matches the callback cookie value."),
				),
			}
		}

		if oauthFlow.ExpiresAt.Before(time.Now()) {
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
					problem_detail_config.WithDetail("The OAuth flow state and callback state do not match."),
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
		if idToken == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("id token")),
			}
		}

		authenticatedIdToken, err := idTokenAuthenticator.Authenticate(ctx, idToken)
		if err != nil {
			wrappedErr := motmedelErrors.New(fmt.Errorf("authenticator authenticate: %w", err), idToken)
			if motmedelErrors.IsAny(err, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("The id token could not be authenticated."),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if authenticatedIdToken == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("authenticated id token")),
			}
		}

		authentication, err := handleAuthenticatedIdToken(ctx, authenticatedIdToken)
		if err != nil {
			if errors.Is(err, ssoErrors.ErrForbiddenUser) {
				return nil, &response_error.ResponseError{
					ClientError:   err,
					ProblemDetail: problem_detail.New(http.StatusForbidden),
				}
			}
		}
		if authentication == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("authentication")),
			}
		}
		authenticationId := authentication.Id
		if authenticationId == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication id")),
			}
		}

		dbscChallenge, err := session.GenerateDbscChallenge()
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("generate dbsc challenge: %w", err)),
			}
		}
		if dbscChallenge == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("dbsc challenge")),
			}
		}

		if err = insertDbscChallenge(ctx, dbscChallenge, authenticationId); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("insert dbsc challenge: %w", err)),
			}
		}

		response, responseError := sessionManager.CreateSession(authentication, dbscChallenge)
		if responseError != nil {
			return nil, responseError
		}
		if response == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("response")),
			}
		}

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

func New(path string, options ...callback_endpoint_config.Option) (*Endpoint, error) {
	if path == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("path"))
	}

	config := callback_endpoint_config.New(options...)
	return &Endpoint{
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
	}, nil
}
