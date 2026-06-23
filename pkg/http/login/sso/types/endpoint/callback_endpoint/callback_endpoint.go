package callback_endpoint

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelDatabase "github.com/Motmedel/utils_go/pkg/database"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelHttpContext "github.com/Motmedel/utils_go/pkg/http/context"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor/query_extractor_config"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	motmedelJws "github.com/Motmedel/utils_go/pkg/json/jose/jws"
	authenticatorPkg "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	motmedelOauth2 "github.com/Motmedel/utils_go/pkg/oauth2"
	motmedelOauth2Config "github.com/Motmedel/utils_go/pkg/oauth2/types/config"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/oauth_flow"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authentication_method"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors/oauth_error"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/provider_claims"
)

type UrlInput struct {
	State        string `json:"state"`
	Code         string `json:"code,omitzero"`
	Scope        string `json:"scope,omitzero"`
	AuthUser     int    `json:"authuser,omitzero"`
	HostedDomain string `json:"hd,omitzero"`
	Prompt       string `json:"prompt,omitzero"`
	SessionState string `json:"session_state,omitzero"`

	// OAuth 2.0 authorization error response parameters (RFC 6749 §4.1.2.1). The
	// provider sets these instead of `code` when authorization does not succeed,
	// e.g. when the user declines consent or cancels (error=access_denied).
	// ErrorSubcode is a Microsoft extension (e.g. error_subcode=cancel).
	Error            string `json:"error,omitzero"`
	ErrorSubcode     string `json:"error_subcode,omitzero"`
	ErrorDescription string `json:"error_description,omitzero"`
	ErrorUri         string `json:"error_uri,omitzero"`
}

var urlInputParser = query_extractor.New[*UrlInput](query_extractor_config.WithAllowAdditionalParameters(true))

type Endpoint[T provider_claims.ProviderClaims] struct {
	*initialization_endpoint.Endpoint
	CallbackCookieName    string
	DbscChallengeDuration time.Duration
	popOauthFlow          func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error)
}

func (e *Endpoint[T]) Initialize(
	oauthConfig *motmedelOauth2Config.Config,
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

		clearedCallbackCookie := http.Cookie{
			Name:     e.CallbackCookieName,
			Path:     e.Path,
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}

		// If the provider returned an error instead of an authorization code (e.g.
		// the user declined consent or cancelled: error=access_denied), this is an
		// expected outcome rather than a server fault. Clear the callback cookie and
		// send the user back to where the flow originated instead of surfacing a 400.
		if urlInput.Error != "" {
			oauthError := oauth_error.New(
				urlInput.Error,
				urlInput.ErrorSubcode,
				urlInput.ErrorDescription,
				urlInput.ErrorUri,
			)

			// Bridge the mux's HTTP context onto the logging context so the
			// registered http_context_extractor populates the ECS http/url/client/...
			// fields. The mux only does this automatically when it handles a
			// ResponseError, which is deliberately avoided here.
			logCtx := ctx
			if httpContext, ok := ctx.Value(muxPkg.MuxHttpContextContextKey).(*motmedelHttpTypes.HttpContext); ok {
				logCtx = motmedelHttpContext.WithHttpContextValue(ctx, httpContext)
			}

			slog.WarnContext(
				motmedelContext.WithError(logCtx, motmedelErrors.NewWithTrace(oauthError)),
				"An OAuth error occurred.",
				slog.Group(
					"event",
					slog.String("reason", "An OAuth error occurred."),
					slog.String("action", "log_oauth_error"),
				),
			)

			return &muxResponse.Response{
				StatusCode: http.StatusSeeOther,
				Headers: []*muxResponse.HeaderEntry{
					{Name: "Location", Value: oauthFlow.RedirectUrl},
					{Name: "Set-Cookie", Value: clearedCallbackCookie.String()},
				},
			}, nil
		}

		if urlInput.Code == "" {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(empty_error.New("code")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Missing authorization code."),
				),
			}
		}

		token, err := oauthConfig.Exchange(ctx, urlInput.Code, motmedelOauth2.VerifierOption(oauthFlow.CodeVerifier))
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

		_, idTokenPayload, _, err := motmedelJws.Parse(idToken)
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

		idTokenHash := sha256.Sum256([]byte(idToken))

		response, responseError := sessionManager.CreateSession(ctx, authentication_method.Sso, strings.ToLower(emailAddress), idTokenHash[:])
		if responseError != nil {
			return nil, responseError
		}
		if response == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("response")),
			}
		}

		response.StatusCode = http.StatusSeeOther

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
