package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux"
	bodyParserAdapter "github.com/Motmedel/utils_go/pkg/http/mux/interfaces/body_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/parsing"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	jsonSchemaBodyParser "github.com/Motmedel/utils_go/pkg/http/mux/utils/json/schema"
	"github.com/Motmedel/utils_go/pkg/http/mux/utils/query"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	"github.com/Motmedel/utils_go/pkg/utils"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
	googleHelpers "github.com/altshiftab/gcp_utils/pkg/http/login/sso/providers/google/helpers"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/providers/google/types"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/providers/google/types/path_config"
	types2 "github.com/altshiftab/gcp_utils/pkg/http/login/sso/types"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	ErrNilEndpointSpecificationOverview = errors.New("nil endpoint specification overview")
)

type UserHandler interface {
	AddEmailAddressUser(ctx context.Context, userEmailAddress string) (userId string, err error)
}

type SessionHandler interface {
	AddCodeVerifier(ctx context.Context, codeVerifier string, redirectUrl string) (codeVerifierId string, err error)
	DeleteCodeVerifier(ctx context.Context, codeVerifierId string) (codeVerifier string, redirectUrl string, err error)
	HandleSuccessfulAuthentication(ctx context.Context, userId string) ([]*muxResponse.HeaderEntry, error)
}

func MakeEndpoints(
	sessionHandler SessionHandler,
	userHandler UserHandler,
	redirectUrlRequestParser request_parser.RequestParser[*url.URL],
	oauthConfig *oauth2.Config,
	oidcVerifier *oidc.IDTokenVerifier,
	options ...path_config.Option,
) (*types.EndpointSpecificationOverview, error) {
	if utils.IsNil(sessionHandler) {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	if utils.IsNil(userHandler) {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilUserHandler)
	}

	if oauthConfig == nil {
		return nil, motmedelErrors.NewWithTrace(ssoErrors.ErrNilOauth2Configuration)
	}

	if oidcVerifier == nil {
		return nil, motmedelErrors.NewWithTrace(ssoErrors.ErrNilTokenVerifier)
	}

	fedCmInputBodyParser, err := jsonSchemaBodyParser.New[*types.FedCmInput]()
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("json schema body parser new (fed cm input): %w", err))
	}

	pathConfig := path_config.New(options...)

	loginEndpointSpecification := &endpoint_specification.EndpointSpecification{
		Path:                   pathConfig.LoginPath,
		Method:                 http.MethodGet,
		UrlParserConfiguration: &parsing.UrlParserConfiguration{Parser: adapter.New(redirectUrlRequestParser)},
		Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			redirectUrl, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*url.URL](ctx)
			if responseError != nil {
				return nil, responseError
			}

			codeVerifier, err := sso.MakeCodeVerifier()
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("make code verifier: %w", err)),
				}
			}

			redirectUrlString := redirectUrl.String()
			codeVerifierId, err := sessionHandler.AddCodeVerifier(ctx, codeVerifier, redirectUrlString)
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("session handler add code verifier: %w", err),
						sessionHandler, codeVerifier, redirectUrlString,
					),
				}
			}

			return &muxResponse.Response{
				StatusCode: http.StatusFound,
				Headers: []*muxResponse.HeaderEntry{
					{
						Name:  "Location",
						Value: oauthConfig.AuthCodeURL(codeVerifierId, oauth2.S256ChallengeOption(codeVerifier)),
					},
				},
			}, nil
		},
	}

	callbackEndpointSpecification := &endpoint_specification.EndpointSpecification{
		Path:   pathConfig.CallbackPath,
		Method: http.MethodGet,
		UrlParserConfiguration: &parsing.UrlParserConfiguration{
			Parser: adapter.New(&query.Parser[*types2.CallbackUrlInput]{}),
		},
		Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			urlInput, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*types2.CallbackUrlInput](ctx)
			if responseError != nil {
				return nil, responseError
			}

			state := urlInput.State
			codeVerifier, redirectUrlString, err := sessionHandler.DeleteCodeVerifier(ctx, state)
			if err != nil {
				wrappedErr := motmedelErrors.New(fmt.Errorf("session handler delete code verifier: %w", err), state)
				if motmedelErrors.IsAny(err, altshiftGcpUtilsHttpLoginErrors.ErrNoChallenge, altshiftGcpUtilsHttpLoginErrors.ErrExpiredChallenge) {
					return nil, &muxResponseError.ResponseError{
						ProblemDetail: problem_detail.MakeBadRequestProblemDetail("Invalid state.", nil),
						ClientError:   wrappedErr,
					}
				}
				return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
			}

			code := urlInput.Code
			token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(
						fmt.Errorf("oauth2 config exchange: %w", err),
						oauthConfig, code, codeVerifier,
					),
				}
			}
			if token == nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(ssoErrors.ErrNilOauth2Token),
				}
			}

			idToken := token.Extra("id_token")
			accessToken, err := utils.ConvertToNonZero[string](idToken)
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("convert to non zero (id token): %w", err),
						idToken,
					),
				}
			}

			userEmailAddress, err := googleHelpers.HandleGoogleToken(ctx, accessToken, oidcVerifier)
			if err != nil {
				wrappedErr := motmedelErrors.New(fmt.Errorf("handle google token: %w", err), accessToken)
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
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("user handler insert email address user: %w", err),
						userHandler, userEmailAddress,
					),
				}
			}

			headerEntries, err := sessionHandler.HandleSuccessfulAuthentication(ctx, userId)
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("session handler handle successful authentication: %w", err),
						sessionHandler, userId,
					),
				}
			}

			headerEntries = append(
				headerEntries,
				&muxResponse.HeaderEntry{Name: "Location", Value: redirectUrlString},
			)

			return &muxResponse.Response{StatusCode: http.StatusSeeOther, Headers: headerEntries}, nil
		},
	}

	fedCmEndpointSpecification := &endpoint_specification.EndpointSpecification{
		Path:   pathConfig.FedcmLoginPath,
		Method: http.MethodPost,
		BodyParserConfiguration: &parsing.BodyParserConfiguration{
			ContentType: "application/json",
			MaxBytes:    8192,
			Parser:      bodyParserAdapter.New(fedCmInputBodyParser),
		},
		Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			fedCmInput, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*types.FedCmInput](ctx)
			if responseError != nil {
				return nil, responseError
			}

			accessToken := fedCmInput.Token

			userEmailAddress, err := googleHelpers.HandleGoogleToken(ctx, accessToken, oidcVerifier)
			if err != nil {
				wrappedErr := motmedelErrors.New(fmt.Errorf("handle google token: %w", err), accessToken)
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
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("user handler insert email address user: %w", err),
						userHandler, userEmailAddress,
					),
				}
			}

			headerEntries, err := sessionHandler.HandleSuccessfulAuthentication(ctx, userId)
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("session handler handle successful authentication: %w", err),
						sessionHandler, userId,
					),
				}
			}

			return &muxResponse.Response{Headers: headerEntries}, nil
		},
	}

	return &types.EndpointSpecificationOverview{
		LoginEndpoint:    loginEndpointSpecification,
		CallbackEndpoint: callbackEndpointSpecification,
		FedCmEndpoint:    fedCmEndpointSpecification,
	}, nil
}

func PatchMux(
	mux *mux.Mux,
	sessionHandler SessionHandler,
	userHandler UserHandler,
	redirectUrlRequestParser request_parser.RequestParser[*url.URL],
	oauthConfig *oauth2.Config,
	oidcVerifier *oidc.IDTokenVerifier,
) error {
	if utils.IsNil(sessionHandler) {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	if utils.IsNil(userHandler) {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilUserHandler)
	}

	if oauthConfig == nil {
		return motmedelErrors.NewWithTrace(ssoErrors.ErrNilOauth2Configuration)
	}

	if oidcVerifier == nil {
		return motmedelErrors.NewWithTrace(ssoErrors.ErrNilTokenVerifier)
	}

	if mux == nil {
		return nil
	}

	overview, err := MakeEndpoints(sessionHandler, userHandler, redirectUrlRequestParser, oauthConfig, oidcVerifier)
	if err != nil {
		return fmt.Errorf("make endpoints: %w", err)
	}
	if overview == nil {
		return motmedelErrors.NewWithTrace(ErrNilEndpointSpecificationOverview)
	}

	mux.Add(overview.LoginEndpoint, overview.CallbackEndpoint, overview.FedCmEndpoint)

	return nil
}
