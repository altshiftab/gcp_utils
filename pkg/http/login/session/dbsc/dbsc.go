package dbsc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux"
	muxErrors "github.com/Motmedel/utils_go/pkg/http/mux/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/parsing"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	"github.com/Motmedel/utils_go/pkg/interfaces/comparer"
	motmedelJwt "github.com/Motmedel/utils_go/pkg/jwt"
	"github.com/Motmedel/utils_go/pkg/jwt/validation/types/base_validator"
	"github.com/Motmedel/utils_go/pkg/jwt/validation/types/header_validator"
	"github.com/Motmedel/utils_go/pkg/jwt/validation/types/jwk_validator"
	"github.com/Motmedel/utils_go/pkg/jwt/validation/types/registered_claims_validator"
	"github.com/Motmedel/utils_go/pkg/jwt/validation/types/setting"
	motmedelNetErrors "github.com/Motmedel/utils_go/pkg/net/errors"
	motmedelTimeErrors "github.com/Motmedel/utils_go/pkg/time/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session"
	dbscErrors "github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/errors"
	dbscHelpers "github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/helpers"
	dbscTypes "github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/dbsc_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/session_registration_response"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/helpers"
)

const (
	sessionResponseHeaderName = "Sec-Session-Response"
	sessionIdHeaderName       = "Sec-Session-Id"
)

type ParsedInput struct {
	PublicKey        []byte
	DbscSessionId    string
	AuthenticationId string
	UserId           string
}

func makeAudienceValue(origin url.URL, endpoint string) string {
	origin.Path = path.Join(origin.Path, endpoint)
	return origin.String()
}

type SessionHandler interface {
	GetAuthenticationPublicKey(ctx context.Context, authenticationId string) ([]byte, error)
	SetAuthenticationPublicKey(ctx context.Context, authenticationId string, publicKey []byte) error
	InsertDbscChallenge(ctx context.Context, challenge string, authenticationId string) error
	DeleteDbscChallenge(ctx context.Context, challenge string, authenticationId string) (userId string, err error)
	MakeSessionSetCookie(ctx context.Context, authenticationId string, userId string, issuer string) (*muxResponse.HeaderEntry, error)
	GetCookieName() string
	GetDbscConfig() *dbsc_config.Config
	GetRegisteredDomain() string
	GetSessionRequestParser() request_parser.RequestParser[session.SessionInput]
}

func MakeEndpoints(sessionHandler SessionHandler) (*dbscTypes.EndpointSpecificationOverview, error) {
	if utils.IsNil(sessionHandler) {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	sessionRequestParser := sessionHandler.GetSessionRequestParser()
	if utils.IsNil(sessionRequestParser) {
		return nil, motmedelErrors.NewWithTrace(muxErrors.ErrNilRequestParser)
	}

	cookieName := sessionHandler.GetCookieName()
	if cookieName == "" {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptySessionCookieName)
	}

	registeredDomain := sessionHandler.GetRegisteredDomain()
	if registeredDomain == "" {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptyRegisteredDomain)
	}

	config := sessionHandler.GetDbscConfig()
	if config == nil {
		return nil, motmedelErrors.NewWithTrace(dbsc_config.ErrNilConfig)
	}

	originUrl := config.OriginUrl
	if originUrl == nil {
		return nil, motmedelErrors.NewWithTrace(motmedelNetErrors.ErrNilUrl)
	}

	registerPath := config.RegisterPath
	refreshPath := config.RefreshPath

	registerAudience := makeAudienceValue(*originUrl, registerPath)
	refreshAudience := makeAudienceValue(*originUrl, refreshPath)

	handleSessionResponse := func(
		ctx context.Context,
		tokenString string,
		authenticationId string,
		dbscSessionId string,
		expectedAudience string,
	) (any, *muxResponseError.ResponseError) {
		var userId string

		_, jwkKey, err := motmedelJwt.ParseAndCheckJwkWithValidator(
			tokenString,
			&jwk_validator.JwkValidator{
				BaseValidator: base_validator.BaseValidator{
					HeaderValidator: &header_validator.HeaderValidator{
						Settings: map[string]setting.Setting{
							"alg": setting.SettingRequired,
							"typ": setting.SettingRequired,
						},
						Expected: &header_validator.ExpectedFields{
							Alg: comparer.NewEqualComparer(config.AllowedAlgs...),
							Typ: comparer.NewEqualComparer("dbsc+jwt"),
						},
					},
					PayloadValidator: &registered_claims_validator.RegisteredClaimsValidator{
						Settings: map[string]setting.Setting{
							"aud": setting.SettingRequired,
							"iat": setting.SettingRequired,
							"jti": setting.SettingRequired,
							"key": setting.SettingRequired,
						},
						Expected: &registered_claims_validator.ExpectedRegisteredClaims{
							AudienceComparer: comparer.NewEqualComparer(expectedAudience),
							IdComparer: comparer.ComparerFunction[string](
								func(jtiChallenge string) (bool, error) {
									var err error
									userId, err = sessionHandler.DeleteDbscChallenge(ctx, jtiChallenge, authenticationId)
									if err != nil {
										if motmedelErrors.IsAny(err, altshiftGcpUtilsHttpLoginErrors.ErrEmptyChallenge, motmedelTimeErrors.ErrExpired) {
											return false, nil
										}

										return false, motmedelErrors.New(
											fmt.Errorf("session handler delete dbsc challenge: %w", err),
											sessionHandler, jtiChallenge, authenticationId,
										)
									}

									return true, nil
								},
							),
						},
					},
				},
			},
		)
		if err != nil {
			wrappedErr := motmedelErrors.New(
				fmt.Errorf("parse and check jwk with validator: %w", err),
				tokenString, authenticationId,
			)
			if motmedelErrors.IsAny(wrappedErr, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError, motmedelErrors.ErrParseError) {
				return nil, &muxResponseError.ResponseError{
					ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
						fmt.Sprintf("Invalid %s header.", sessionResponseHeaderName),
						nil,
					),
					ClientError: wrappedErr,
				}
			}

			return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
		}

		return &ParsedInput{
			PublicKey:        jwkKey,
			DbscSessionId:    dbscSessionId,
			AuthenticationId: authenticationId,
			UserId:           userId,
		}, nil
	}

	registerRequestParser := request_parser.RequestParserFunction[any](
		func(request *http.Request) (any, *muxResponseError.ResponseError) {
			if request == nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequest),
				}
			}

			requestHeader := request.Header
			if requestHeader == nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequestHeader),
				}
			}

			sessionInput, responseError := sessionRequestParser.Parse(request)
			if responseError != nil {
				return nil, responseError
			}

			if _, ok := requestHeader[sessionResponseHeaderName]; !ok {
				return nil, &muxResponseError.ResponseError{
					ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
						fmt.Sprintf("Missing %s header.", sessionResponseHeaderName),
						nil,
					),
				}
			}

			sessionResponseJwkString := requestHeader.Get(sessionResponseHeaderName)
			if sessionResponseJwkString == "" {
				return nil, &muxResponseError.ResponseError{
					ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
						fmt.Sprintf("Empty %s header.", sessionResponseHeaderName),
						nil,
					),
				}
			}

			return handleSessionResponse(
				request.Context(),
				sessionResponseJwkString,
				sessionInput.GetAuthenticationId(),
				sessionInput.GetId(),
				registerAudience,
			)
		},
	)

	refreshRequestParser := request_parser.RequestParserFunction[any](
		func(request *http.Request) (any, *muxResponseError.ResponseError) {
			if request == nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequest),
				}
			}

			requestHeader := request.Header
			if requestHeader == nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequestHeader),
				}
			}

			if _, ok := requestHeader[sessionIdHeaderName]; !ok {
				return nil, &muxResponseError.ResponseError{
					ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
						fmt.Sprintf("Missing %s header.", sessionIdHeaderName),
						nil,
					),
				}
			}

			dbscSessionId := requestHeader.Get(sessionIdHeaderName)

			authenticationId, _, found := strings.Cut(dbscSessionId, ":")
			if !found {
				return nil, &muxResponseError.ResponseError{
					ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
						fmt.Sprintf("Malformed %s header.", sessionIdHeaderName),
						nil,
					),
					ClientError: motmedelErrors.NewWithTrace(
						fmt.Errorf("%w (claims id)", motmedelErrors.ErrBadSplit),
						dbscSessionId,
					),
				}
			}

			if _, ok := requestHeader[sessionResponseHeaderName]; !ok {
				return &ParsedInput{
					PublicKey:        nil,
					DbscSessionId:    dbscSessionId,
					AuthenticationId: authenticationId,
				}, nil
			}

			sessionResponseJwkString := requestHeader.Get(sessionResponseHeaderName)
			if sessionResponseJwkString == "" {
				return nil, &muxResponseError.ResponseError{
					ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
						fmt.Sprintf("Empty %s header.", sessionResponseHeaderName),
						nil,
					),
				}
			}

			return handleSessionResponse(
				request.Context(),
				sessionResponseJwkString,
				authenticationId,
				dbscSessionId,
				refreshAudience,
			)
		},
	)

	registerEndpoint := &endpoint_specification.EndpointSpecification{
		Path:                      registerPath,
		Method:                    http.MethodPost,
		HeaderParserConfiguration: &parsing.HeaderParserConfiguration{Parser: registerRequestParser},
		BodyParserConfiguration:   &parsing.BodyParserConfiguration{EmptyOption: parsing.BodyForbidden},
		Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			parsedInput, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[*ParsedInput](ctx)
			if responseError != nil {
				return nil, responseError
			}

			authenticationId := parsedInput.AuthenticationId
			publicKey := parsedInput.PublicKey
			if err := sessionHandler.SetAuthenticationPublicKey(ctx, authenticationId, publicKey); err != nil {
				return nil, &muxResponseError.ResponseError{ServerError: motmedelErrors.New(
					fmt.Errorf("session handler set authentication public key: %w", err),
					sessionHandler, authenticationId, publicKey,
				)}
			}

			response := session_registration_response.SessionRegistrationResponse{
				SessionIdentifier: parsedInput.DbscSessionId,
				RefreshURL:        refreshPath,
				Scope: session_registration_response.Scope{
					Origin:      fmt.Sprintf("https://%s", registeredDomain),
					IncludeSite: true,
				},
				Credentials: []session_registration_response.Credential{
					{
						Type:       "cookie",
						Name:       cookieName,
						Attributes: helpers.GetSessionCookieAttributes(registeredDomain),
					},
				},
			}

			responseData, err := json.Marshal(response)
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("json marshal (response data): %w", err),
						response,
					),
				}
			}

			return &muxResponse.Response{
				Headers: []*muxResponse.HeaderEntry{{Name: "Content-Type", Value: "application/json"}},
				Body:    responseData,
			}, nil
		},
	}

	refreshEndpoint := &endpoint_specification.EndpointSpecification{
		Path:                      refreshPath,
		Method:                    http.MethodPost,
		HeaderParserConfiguration: &parsing.HeaderParserConfiguration{Parser: refreshRequestParser},
		Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			parsedInput, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[*ParsedInput](ctx)
			if responseError != nil {
				return nil, responseError
			}

			publicKey := parsedInput.PublicKey
			if publicKey == nil {
				challenge, err := dbscHelpers.GenerateChallenge()
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: fmt.Errorf("generate challenge: %w", err),
					}
				}

				authenticationId := parsedInput.AuthenticationId
				if err := sessionHandler.InsertDbscChallenge(ctx, challenge, authenticationId); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("session handler insert dbsc challenge: %w", err),
							sessionHandler, challenge, authenticationId,
						),
					}
				}

				return &muxResponse.Response{
					StatusCode: http.StatusUnauthorized,
					Headers: []*muxResponse.HeaderEntry{
						{
							Name: "Sec-Session-Challenge",
							Value: fmt.Sprintf(
								"\"%s\";id=\"%s\"",
								challenge,
								parsedInput.DbscSessionId,
							),
						},
					},
				}, nil
			}

			authenticationId := parsedInput.AuthenticationId
			authenticationPublicKey, err := sessionHandler.GetAuthenticationPublicKey(ctx, authenticationId)
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("session handler get authentication public key: %w", err),
						sessionHandler, authenticationId,
					),
				}
			}
			if len(authenticationPublicKey) == 0 {
				return nil, &muxResponseError.ResponseError{
					ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
						"No public key for authentication.",
						nil,
					),
				}
			}

			if !bytes.Equal(authenticationPublicKey, publicKey) {
				return nil, &muxResponseError.ResponseError{
					ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
						"Public key mismatch.",
						nil,
					),
					ClientError: motmedelErrors.New(
						dbscErrors.ErrPublicKeyMismatch,
						authenticationPublicKey, publicKey,
					),
				}
			}

			userId := parsedInput.UserId
			headerEntry, err := sessionHandler.MakeSessionSetCookie(ctx, authenticationId, userId, "dbsc")
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(
						fmt.Errorf("session handler make session header: %w", err),
						sessionHandler, authenticationId, userId,
					),
				}
			}
			if headerEntry == nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionCookieHeaderEntry),
				}
			}

			return &muxResponse.Response{Headers: []*muxResponse.HeaderEntry{headerEntry}}, nil
		},
	}

	return &dbscTypes.EndpointSpecificationOverview{
		RefreshEndpoint:  refreshEndpoint,
		RegisterEndpoint: registerEndpoint,
	}, nil
}

func PatchMux(
	mux *mux.Mux,
	sessionHandler SessionHandler,
	cookieName string,
	registeredDomain string,
) error {
	if utils.IsNil(sessionHandler) {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	sessionRequestParser := sessionHandler.GetSessionRequestParser()
	if utils.IsNil(sessionRequestParser) {
		return motmedelErrors.NewWithTrace(muxErrors.ErrNilRequestParser)
	}

	if cookieName == "" {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptySessionCookieName)
	}

	if registeredDomain == "" {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptyRegisteredDomain)
	}

	if mux == nil {
		return nil
	}

	overview, err := MakeEndpoints(sessionHandler)
	if err != nil {
		return fmt.Errorf("make endpoints: %w", err)
	}

	mux.Add(overview.RefreshEndpoint, overview.RegisterEndpoint)

	return nil
}
