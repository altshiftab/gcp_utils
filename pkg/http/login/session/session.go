package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux"
	muxErrors "github.com/Motmedel/utils_go/pkg/http/mux/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/parsing"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	"github.com/Motmedel/utils_go/pkg/utils"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/path_config"
)

type SessionInput interface {
	GetAuthenticationId() string
	GetId() string
	GetUsesDbsc() bool
	GetIsFirstSession() bool
	GetExpiresAt() time.Time
	GetNotBefore() time.Time
	GetUserId() string
}

type SessionHandler interface {
	GetAuthenticationPublicKey(ctx context.Context, authenticationId string) ([]byte, error)
	MakeSessionSetCookie(ctx context.Context, authenticationId string, userId string, sessionType string) (*muxResponse.HeaderEntry, error)
	EndSession(ctx context.Context, authenticationId string) error
	GetSessionRequestParser() request_parser.RequestParser[SessionInput]
}

func MakeEndpoints(sessionHandler SessionHandler, options ...path_config.Option) (*types.EndpointSpecificationOverview, error) {
	if utils.IsNil(sessionHandler) {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	sessionRequestParser := sessionHandler.GetSessionRequestParser()
	if utils.IsNil(sessionRequestParser) {
		return nil, motmedelErrors.NewWithTrace(muxErrors.ErrNilRequestParser)
	}

	pathConfig := path_config.New(options...)

	headerParser := adapter.New(sessionHandler.GetSessionRequestParser())

	refreshEndpointSpecification := &endpoint_specification.EndpointSpecification{
		Path:                      pathConfig.RefreshPath,
		Method:                    http.MethodPost,
		HeaderParserConfiguration: &parsing.HeaderParserConfiguration{Parser: headerParser},
		Handler: func(request *http.Request, bytes []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			sessionInput, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[SessionInput](ctx)
			if responseError != nil {
				return nil, responseError
			}

			if sessionInput.GetUsesDbsc() {
				// Session refresh is handled by the DBSC mechanism. Done here.
				return nil, nil
			}

			// Don't refresh if this is the first session and DBSC has been added.
			authenticationId := sessionInput.GetAuthenticationId()
			if sessionInput.GetIsFirstSession() {
				publicKey, err := sessionHandler.GetAuthenticationPublicKey(ctx, authenticationId)
				if err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("session handler get authentication public key: %w", err),
						authenticationId,
					)
					if errors.Is(err, altshiftGcpUtilsHttpLoginErrors.ErrNoAuthenticationPublicKey) {
						return nil, &muxResponseError.ResponseError{
							ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
								http.StatusUnauthorized,
								"The session's authentication no longer exists.",
								nil,
							),
							ServerError: wrappedErr,
						}
					}

					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}

				if len(publicKey) != 0 {
					// Session refresh is handled by the DBSC mechanism. Done here.
					return nil, nil
				}
			}

			sessionExpiresAt := sessionInput.GetExpiresAt()
			remainingExpirationDuration := time.Until(sessionExpiresAt)
			if remainingExpirationDuration < 0 {
				return nil, &muxResponseError.ResponseError{
					ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
						http.StatusUnauthorized,
						"",
						nil,
					),
					ClientError: motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNegativeDuration),
				}
			}

			// The session token should be refreshed if one third or less of its expiration duration remains.
			if remainingExpirationDuration > (sessionExpiresAt.Sub(sessionInput.GetNotBefore()) / 3) {
				return nil, nil
			}

			userId := sessionInput.GetUserId()

			headerEntry, err := sessionHandler.MakeSessionSetCookie(ctx, authenticationId, userId, "refresh")
			if err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("session handler make header: %w", err),
						authenticationId, userId,
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

	endEndpointSpecification := &endpoint_specification.EndpointSpecification{
		Path:                      "/api/session/end",
		Method:                    http.MethodPost,
		HeaderParserConfiguration: &parsing.HeaderParserConfiguration{Parser: headerParser},
		Handler: func(request *http.Request, bytes []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
			ctx := request.Context()

			sessionInput, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[SessionInput](ctx)
			if responseError != nil {
				return nil, responseError
			}

			authenticationId := sessionInput.GetAuthenticationId()
			if err := sessionHandler.EndSession(ctx, authenticationId); err != nil {
				return nil, &muxResponseError.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("session handler end session: %w", err),
						sessionHandler, authenticationId,
					),
				}
			}

			return &muxResponse.Response{
				Headers: []*muxResponse.HeaderEntry{{Name: "Clear-Site-Data", Value: `"cookies"`}},
			}, nil
		},
	}

	return &types.EndpointSpecificationOverview{
		RefreshEndpoint: refreshEndpointSpecification,
		EndEndpoint:     endEndpointSpecification,
	}, nil
}

func PatchMux(
	mux *mux.Mux,
	sessionHandler SessionHandler,
	options ...path_config.Option,
) error {
	if utils.IsNil(sessionHandler) {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	if mux == nil {
		return nil
	}

	endpointSpecifications, err := MakeEndpoints(sessionHandler, options...)
	if err != nil {
		return fmt.Errorf("make endpoints: %w", err)
	}

	mux.Add(endpointSpecifications.RefreshEndpoint, endpointSpecifications.EndEndpoint)

	return nil
}
