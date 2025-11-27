package microsoft

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux"
	bodyParserAdapter "github.com/Motmedel/utils_go/pkg/http/mux/interfaces/body_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/processor"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/request_parser"
	requestParserAdapter "github.com/Motmedel/utils_go/pkg/http/mux/interfaces/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/parsing"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/mux/utils/client_side_encryption"
	jsonSchemaBodyParser "github.com/Motmedel/utils_go/pkg/http/mux/utils/json/schema"
	"github.com/Motmedel/utils_go/pkg/http/mux/utils/query"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	motmedelTimeErrors "github.com/Motmedel/utils_go/pkg/time/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
	microsoftHelpers "github.com/altshiftab/gcp_utils/pkg/http/login/sso/providers/microsoft/helpers"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/providers/microsoft/types"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/providers/microsoft/types/path_config"
	ssoTypes "github.com/altshiftab/gcp_utils/pkg/http/login/sso/types"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/cse_config"
	"github.com/coreos/go-oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

var (
	ErrNilEndpointSpecificationOverview = errors.New("nil endpoint specification overview")
)

type UserHandler interface {
	AddEmailAddressUser(ctx context.Context, userEmailAddress string) (userId string, err error)
}

type SessionHandler interface {
	AddOauthFlow(ctx context.Context, oauthFlow *ssoTypes.OauthFlow) (oauthFlowId string, err error)
	DeleteOauthFlow(ctx context.Context, oauthFlowId string) (*ssoTypes.OauthFlow, error)
	HandleSuccessfulWebAuthentication(ctx context.Context, userId string) ([]*muxResponse.HeaderEntry, error)
	MakeSessionToken(ctx context.Context, userId string) (string, error)
}

func handleExchange(
	ctx context.Context,
	code string,
	verifier string,
	oauthConfig *oauth2.Config,
	oidcVerifier *oidc.IDTokenVerifier,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context err: %w", err)
	}

	if code == "" {
		return "", motmedelErrors.NewWithTrace(ssoErrors.ErrEmptyCode)
	}

	if verifier == "" {
		return "", motmedelErrors.NewWithTrace(ssoErrors.ErrEmptyCodeVerifier)
	}

	if oauthConfig == nil {
		return "", motmedelErrors.NewWithTrace(ssoErrors.ErrNilOauth2Configuration)
	}

	if oidcVerifier == nil {
		return "", motmedelErrors.NewWithTrace(ssoErrors.ErrNilTokenVerifier)
	}

	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", fmt.Errorf("oauth2 config exchange: %w", err)
	}
	if token == nil {
		return "", motmedelErrors.NewWithTrace(ssoErrors.ErrNilOauth2Token)
	}

	idToken := token.Extra("id_token")
	accessToken, err := utils.ConvertToNonZero[string](idToken)
	if err != nil {
		return "", motmedelErrors.New(fmt.Errorf("convert to non zero (id token): %w", err), idToken)
	}

	userEmailAddress, err := microsoftHelpers.HandleMicrosoftToken(ctx, accessToken, oidcVerifier)
	if err != nil {
		return "", motmedelErrors.New(fmt.Errorf("handle microsoft token: %w", err), accessToken)
	}

	return userEmailAddress, nil
}

func MakeEndpoints(
	sessionHandler SessionHandler,
	userHandler UserHandler,
	callbackCookieName string,
	redirectUrlRequestParser request_parser.RequestParser[*url.URL],
	oauthConfig *oauth2.Config,
	oidcVerifier *oidc.IDTokenVerifier,
	cseConfig *cse_config.Config,
	options ...path_config.Option,
) (*types.EndpointSpecificationOverview, error) {
	if utils.IsNil(sessionHandler) {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	if utils.IsNil(userHandler) {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilUserHandler)
	}

	if callbackCookieName == "" {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("%w (callback)", motmedelHttpErrors.ErrEmptyCookieName))
	}

	if oauthConfig == nil {
		return nil, motmedelErrors.NewWithTrace(ssoErrors.ErrNilOauth2Configuration)
	}

	if oidcVerifier == nil {
		return nil, motmedelErrors.NewWithTrace(ssoErrors.ErrNilTokenVerifier)
	}

	if cseConfig == nil {
		return nil, motmedelErrors.NewWithTrace(ssoErrors.ErrNilCseConfig)
	}

	tokenInputBodyParser, err := jsonSchemaBodyParser.New[*ssoTypes.TokenInput]()
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("json schema body parser new (token input): %w", err))
	}

	pathConfig := path_config.New(options...)

	loginEndpointSpecification := &endpoint_specification.EndpointSpecification{
		Path:                   pathConfig.LoginPath,
		Method:                 http.MethodGet,
		UrlParserConfiguration: &parsing.UrlParserConfiguration{Parser: requestParserAdapter.New(redirectUrlRequestParser)},
		Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			redirectUrl, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*url.URL](ctx)
			if responseError != nil {
				return nil, responseError
			}

			codeVerifier, err := sso.MakeCodeVerifier()
			if err != nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("make code verifier: %w", err))}
			}

			state, err := sso.MakeState()
			if err != nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("make state: %w", err))}
			}

			oauthFlow := &ssoTypes.OauthFlow{State: state, CodeVerifier: codeVerifier, RedirectUrl: redirectUrl.String()}

			oauthFlowId, err := sessionHandler.AddOauthFlow(ctx, oauthFlow)
			if err != nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.New(
					fmt.Errorf("session handler add code verifier: %w", err),
					sessionHandler, oauthFlow,
				)}
			}

			callbackCookie := http.Cookie{
				Name:     callbackCookieName,
				Value:    oauthFlowId,
				Path:     pathConfig.CallbackPath,
				Expires:  time.Now().Add(3 * time.Minute),
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}

			return &muxResponse.Response{
				StatusCode: http.StatusFound,
				Headers: []*muxResponse.HeaderEntry{
					{Name: "Set-Cookie", Value: callbackCookie.String()},
					{Name: "Location", Value: oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier))},
				},
			}, nil
		},
	}

	callbackEndpointSpecification := &endpoint_specification.EndpointSpecification{
		Path:   pathConfig.CallbackPath,
		Method: http.MethodGet,
		UrlParserConfiguration: &parsing.UrlParserConfiguration{
			Parser: requestParserAdapter.New(&query.Parser[*ssoTypes.CallbackUrlInput]{}),
		},
		Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			urlInput, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*ssoTypes.CallbackUrlInput](ctx)
			if responseError != nil {
				return nil, responseError
			}

			callbackCookie, err := request.Cookie(callbackCookieName)
			if err != nil {
				if errors.Is(err, http.ErrNoCookie) {
					return nil, &muxResponseError.ResponseError{ProblemDetail: problem_detail.MakeBadRequestProblemDetail("No callback cookie.", nil)}
				}
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("request cookie: %w", err), callbackCookieName)}
			}
			if callbackCookie == nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("%w (callback)", motmedelHttpErrors.ErrNilCookie))}
			}

			callbackCookieValue := callbackCookie.Value
			oauthFlow, err := sessionHandler.DeleteOauthFlow(ctx, callbackCookieValue)
			if err != nil {
				wrappedErr := motmedelErrors.New(fmt.Errorf("session handler delete code verifier: %w", err), callbackCookieValue)
				if motmedelErrors.IsAny(err, altshiftGcpUtilsHttpLoginErrors.ErrEmptyChallenge, motmedelTimeErrors.ErrExpired) {
					return nil, &muxResponseError.ResponseError{
						ProblemDetail: problem_detail.MakeBadRequestProblemDetail("Invalid state.", nil),
						ClientError:   wrappedErr,
					}
				}
				return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
			}
			if oauthFlow == nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(ssoErrors.ErrNilOauthFlow)}
			}

			if oauthFlow.State != urlInput.State {
				return nil, &muxResponseError.ResponseError{ProblemDetail: problem_detail.MakeBadRequestProblemDetail("Invalid state.", nil)}
			}

			code := urlInput.Code
			codeVerifier := oauthFlow.CodeVerifier
			userEmailAddress, err := handleExchange(ctx, code, codeVerifier, oauthConfig, oidcVerifier)
			if err != nil {
				wrappedErr := motmedelErrors.New(fmt.Errorf("handle exchange: %w", err), code, codeVerifier, oauthConfig, oidcVerifier)
				if errors.Is(err, motmedelErrors.ErrValidationError) {
					return nil, &muxResponseError.ResponseError{
						ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
							fmt.Sprintf("The access token could not be verified: %v", err),
							nil,
						),
						ClientError: wrappedErr,
					}
				} else {
					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}
			}
			if userEmailAddress == "" {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(ssoErrors.ErrEmptyEmailAddress)}
			}

			userId, err := userHandler.AddEmailAddressUser(ctx, userEmailAddress)
			if err != nil {
				wrappedErr := motmedelErrors.New(fmt.Errorf("handle exchange: %w", err), code, codeVerifier, oauthConfig, oidcVerifier)
				if errors.Is(err, motmedelErrors.ErrValidationError) {
					return nil, &muxResponseError.ResponseError{
						ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
							fmt.Sprintf("The access token could not be verified: %v", err),
							nil,
						),
						ClientError: wrappedErr,
					}
				} else {
					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}
			}

			headerEntries, err := sessionHandler.HandleSuccessfulWebAuthentication(ctx, userId)
			if err != nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.New(
					fmt.Errorf("session handler handle successful authentication: %w", err),
					sessionHandler, userId,
				)}
			}

			clearedCallbackCookie := http.Cookie{
				Name:     callbackCookieName,
				Path:     pathConfig.CallbackPath,
				Expires:  time.Unix(0, 0),
				MaxAge:   -1,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}

			headerEntries = append(headerEntries,
				&muxResponse.HeaderEntry{Name: "Location", Value: oauthFlow.RedirectUrl},
				&muxResponse.HeaderEntry{Name: "Set-Cookie", Value: clearedCallbackCookie.String()},
			)

			return &muxResponse.Response{StatusCode: http.StatusSeeOther, Headers: headerEntries}, nil
		},
	}

	tokenEndpointSpecification := &endpoint_specification.EndpointSpecification{
		Path:   pathConfig.TokenPath,
		Method: http.MethodPost,
		HeaderParserConfiguration: &parsing.HeaderParserConfiguration{
			Parser: requestParserAdapter.New(
				&client_side_encryption.HeaderRequestParser{
					Header:            cseConfig.ClientPublicJwkHeader,
					KeyAlgorithm:      cseConfig.KeyAlgorithm,
					ContentEncryption: cseConfig.ContentEncryption,
					EncrypterOptions:  cseConfig.EncrypterOptions.WithContentType("text/plain"),
				},
			),
		},
		BodyParserConfiguration: &parsing.BodyParserConfiguration{
			ContentType: "application/jose",
			MaxBytes:    4096,
			Parser: bodyParserAdapter.New(
				&muxUtils.BodyParserWithProcessor[[]byte, *ssoTypes.TokenInput]{
					BodyParser: &client_side_encryption.BodyParser{
						PrivateKey:        cseConfig.PrivateKey,
						KeyAlgorithm:      cseConfig.KeyAlgorithm,
						ContentEncryption: cseConfig.ContentEncryption,
					},
					Processor: processor.ProcessorFunction[*ssoTypes.TokenInput, []byte](
						func(decryptedPayload []byte) (*ssoTypes.TokenInput, *muxResponseError.ResponseError) {
							tokenInput, responseError := tokenInputBodyParser.Parse(nil, decryptedPayload)
							if responseError != nil {
								return nil, responseError
							}
							return tokenInput, nil
						},
					),
				},
			),
		},
		Handler: func(request *http.Request, body []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			responseEncrypter, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[jose.Encrypter](ctx)
			if responseError != nil {
				return nil, responseError
			}

			tokenInput, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*ssoTypes.TokenInput](ctx)
			if responseError != nil {
				return nil, responseError
			}

			code := tokenInput.Code
			codeVerifier := tokenInput.Verifier
			userEmailAddress, err := handleExchange(ctx, code, codeVerifier, oauthConfig, oidcVerifier)
			if err != nil {
				wrappedErr := motmedelErrors.New(fmt.Errorf("handle exchange: %w", err), code, codeVerifier, oauthConfig, oidcVerifier)
				if errors.Is(err, motmedelErrors.ErrValidationError) {
					return nil, &muxResponseError.ResponseError{
						ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
							fmt.Sprintf("The access token could not be verified: %v", err),
							nil,
						),
						ClientError: wrappedErr,
					}
				} else {
					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}
			}

			userId, err := userHandler.AddEmailAddressUser(ctx, userEmailAddress)
			if err != nil {
				wrappedErr := motmedelErrors.New(fmt.Errorf("handle exchange: %w", err), code, codeVerifier, oauthConfig, oidcVerifier)
				if errors.Is(err, motmedelErrors.ErrValidationError) {
					return nil, &muxResponseError.ResponseError{
						ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
							fmt.Sprintf("The access token could not be verified: %v", err),
							nil,
						),
						ClientError: wrappedErr,
					}
				} else {
					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}
			}

			sessionToken, err := sessionHandler.MakeSessionToken(ctx, userId)
			if err != nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.New(
					fmt.Errorf("session handler make session token: %w", err),
					sessionHandler, userId,
				)}
			}
			if sessionToken == "" {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(ssoErrors.ErrEmptySessionToken)}
			}

			jwe, err := responseEncrypter.Encrypt([]byte(sessionToken))
			if err != nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("jose encrypt: %w", err))}
			}
			if jwe == nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(ssoErrors.ErrNilJwe)}
			}

			compact, err := jwe.CompactSerialize()
			if err != nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("json web encryption compact serialize: %w", err))}
			}

			return &muxResponse.Response{Body: []byte(compact), Headers: []*muxResponse.HeaderEntry{{Name: "Content-Type", Value: "application/jose"}}}, nil
		},
	}

	overview := &types.EndpointSpecificationOverview{
		LoginEndpoint:    loginEndpointSpecification,
		CallbackEndpoint: callbackEndpointSpecification,
		TokenEndpoint:    tokenEndpointSpecification,
	}

	return overview, nil
}

func PatchMux(
	mux *mux.Mux,
	sessionHandler SessionHandler,
	userHandler UserHandler,
	callbackCookieName string,
	redirectUrlRequestParser request_parser.RequestParser[*url.URL],
	oauthConfig *oauth2.Config,
	oidcVerifier *oidc.IDTokenVerifier,
	cseConfig *cse_config.Config,
	options ...path_config.Option,
) error {
	if utils.IsNil(sessionHandler) {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	if utils.IsNil(userHandler) {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilUserHandler)
	}

	if callbackCookieName == "" {
		return motmedelErrors.NewWithTrace(fmt.Errorf("%w (callback)", motmedelHttpErrors.ErrEmptyCookieName))
	}

	if oauthConfig == nil {
		return motmedelErrors.NewWithTrace(ssoErrors.ErrNilOauth2Configuration)
	}

	if oidcVerifier == nil {
		return motmedelErrors.NewWithTrace(ssoErrors.ErrNilTokenVerifier)
	}

	if cseConfig == nil {
		return motmedelErrors.NewWithTrace(ssoErrors.ErrNilCseConfig)
	}

	if mux == nil {
		return nil
	}

	overview, err := MakeEndpoints(sessionHandler, userHandler, callbackCookieName, redirectUrlRequestParser, oauthConfig, oidcVerifier, cseConfig, options...)
	if err != nil {
		return err
	}
	if overview == nil {
		return motmedelErrors.NewWithTrace(ErrNilEndpointSpecificationOverview)
	}

	mux.Add(overview.LoginEndpoint, overview.CallbackEndpoint, overview.TokenEndpoint)

	return nil
}
