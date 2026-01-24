package dbsc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux"
	muxErrors "github.com/Motmedel/utils_go/pkg/http/mux/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/parsing"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	requestParserAdapter "github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	motmedelNetErrors "github.com/Motmedel/utils_go/pkg/net/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session"
	dbscErrors "github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/dbsc_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/endpoint_specification_overview"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/parsed_input"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/refresh_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/register_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/session_registration_response"
	sessionErrors "github.com/altshiftab/gcp_utils/pkg/http/login/session/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_cookie"
)

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

func MakeBareEndpoints() *endpoint_specification_overview.EndpointSpecificationOverview {
	registerEndpoint := &endpoint_specification.EndpointSpecification{
		Path:                      dbsc_config.DefaultRegisterPath,
		Method:                    http.MethodPost,
		HeaderParserConfiguration: nil,
		BodyParserConfiguration:   &parsing.BodyParserConfiguration{EmptyOption: parsing.BodyForbidden},
		Handler:                   nil,
	}

	refreshEndpoint := &endpoint_specification.EndpointSpecification{
		Path:                      dbsc_config.DefaultRefreshPath,
		Method:                    http.MethodPost,
		HeaderParserConfiguration: nil,
		Handler:                   nil,
	}

	return &endpoint_specification_overview.EndpointSpecificationOverview{
		RefreshEndpoint:  refreshEndpoint,
		RegisterEndpoint: registerEndpoint,
	}
}

func makeAudienceValue(origin url.URL, endpoint string) string {
	origin.Path = path.Join(origin.Path, endpoint)
	return origin.String()
}

func generateChallenge() (string, error) {
	challenge := make([]byte, 64)
	if _, err := rand.Read(challenge); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return base64.URLEncoding.EncodeToString(challenge), nil
}

func PopulateBareEndpoints(bareEndpointsOverview *endpoint_specification_overview.EndpointSpecificationOverview, sessionHandler SessionHandler) error {
	if utils.IsNil(sessionHandler) {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	sessionRequestParser := sessionHandler.GetSessionRequestParser()
	if utils.IsNil(sessionRequestParser) {
		return motmedelErrors.NewWithTrace(muxErrors.ErrNilRequestParser)
	}

	cookieName := sessionHandler.GetCookieName()
	if cookieName == "" {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptySessionCookieName)
	}

	registeredDomain := sessionHandler.GetRegisteredDomain()
	if registeredDomain == "" {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptyRegisteredDomain)
	}

	config := sessionHandler.GetDbscConfig()
	if config == nil {
		return motmedelErrors.NewWithTrace(dbsc_config.ErrNilConfig)
	}

	originUrl := config.OriginUrl
	if originUrl == nil {
		return motmedelErrors.NewWithTrace(motmedelNetErrors.ErrNilUrl)
	}

	registerPath := config.RegisterPath
	refreshPath := config.RefreshPath

	registerAudience := makeAudienceValue(*originUrl, registerPath)
	registerRequestParser, err := register_request_parser.New(registerAudience, sessionHandler.DeleteDbscChallenge, sessionRequestParser)
	if err != nil {
		return motmedelErrors.New(
			fmt.Errorf("register request parser new: %w", err),
			registerAudience, sessionHandler.DeleteDbscChallenge, sessionRequestParser,
		)
	}

	registerEndpointSpecification := bareEndpointsOverview.RegisterEndpoint
	if registerEndpointSpecification == nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("%w (register)", muxErrors.ErrNilEndpointSpecification))
	}
	registerEndpointSpecification.HeaderParserConfiguration = &parsing.HeaderParserConfiguration{
		Parser: requestParserAdapter.New(registerRequestParser),
	}
	registerEndpointSpecification.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
		ctx := request.Context()

		parsedInput, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[*parsed_input.Input](ctx)
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
					Attributes: session_cookie.Attributes(registeredDomain),
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
	}

	refreshAudience := makeAudienceValue(*originUrl, refreshPath)
	refreshRequestParser, err := refresh_request_parser.New(refreshAudience, sessionHandler.DeleteDbscChallenge)
	if err != nil {
		return motmedelErrors.New(
			fmt.Errorf("refresh request parser new: %w", err),
			refreshAudience, sessionHandler.DeleteDbscChallenge,
		)
	}

	refreshEndpointSpecification := bareEndpointsOverview.RefreshEndpoint
	if refreshEndpointSpecification == nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("%w (refresh)", muxErrors.ErrNilEndpointSpecification))
	}
	refreshEndpointSpecification.HeaderParserConfiguration = &parsing.HeaderParserConfiguration{
		Parser: requestParserAdapter.New(refreshRequestParser),
	}
	refreshEndpointSpecification.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
		ctx := request.Context()

		parsedInput, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[*parsed_input.Input](ctx)
		if responseError != nil {
			return nil, responseError
		}

		publicKey := parsedInput.PublicKey
		if publicKey == nil {
			challenge, err := generateChallenge()
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
	}

	return nil
}

func MakeEndpoints(sessionHandler SessionHandler) (*endpoint_specification_overview.EndpointSpecificationOverview, error) {
	bareEndpointsOverview := MakeBareEndpoints()
	if bareEndpointsOverview == nil {
		return nil, motmedelErrors.NewWithTrace(sessionErrors.ErrNilEndpointSpecificationOverview)
	}

	err := PopulateBareEndpoints(bareEndpointsOverview, sessionHandler)
	if err != nil {
		return nil, fmt.Errorf("populate bare endpoints: %w", err)
	}

	return bareEndpointsOverview, nil
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
