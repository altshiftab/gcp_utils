package dbsc_refresh_endpoint

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"time"

	motmedelDatabase "github.com/Motmedel/utils_go/pkg/database"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/mismatch_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/http/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/dbsc_session_response_processor"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
)

const (
	DbscAuthenticationMethod  = "hwk"
	sessionResponseHeaderName = "Sec-Session-Response"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	SessionDuration   time.Duration
	ChallengeDuration time.Duration
}

func (e *Endpoint) Initialize(
	authorizerRequestParser *authorizer_request_parser.Parser,
	dbscSessionResponseProcessor *dbsc_session_response_processor.Processor,
	sessionManager *session_manager.Manager,
) error {
	if authorizerRequestParser == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("authorizer request parser"))
	}

	if dbscSessionResponseProcessor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("dbsc session response processor"))
	}

	if sessionManager == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager"))
	}

	db := sessionManager.Db
	if db == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager sql db"))
	}

	e.AuthenticationParser = adapter.New(authorizerRequestParser)
	e.HeaderParser = request_parser.New(
		func(request *http.Request) (any, *response_error.ResponseError) {
			if request == nil {
				return nil, &response_error.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(nil_error.New("http request")),
				}
			}
			requestHeader := request.Header
			if requestHeader == nil {
				return nil, &response_error.ResponseError{
					ServerError: motmedelErrors.NewWithTrace(nil_error.New("http request header")),
				}
			}

			sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](request.Context())
			if responseError != nil {
				return nil, responseError
			}

			sessionResponseValue, err := utils.GetSingleHeader(sessionResponseHeaderName, requestHeader)
			if err != nil {
				wrappedErr := motmedelErrors.New(fmt.Errorf("get single header: %w", err))
				if errors.Is(err, motmedelHttpErrors.ErrMissingHeader) {
					return nil, nil
				} else if errors.Is(err, motmedelHttpErrors.ErrMultipleHeaderValues) {
					return nil, &response_error.ResponseError{
						ClientError: wrappedErr,
						ProblemDetail: problem_detail.New(
							http.StatusBadRequest,
							problem_detail_config.WithDetail("Multiple header values."),
							problem_detail_config.WithExtension(map[string]any{"header": sessionResponseHeaderName}),
						),
					}
				}

				return nil, &response_error.ResponseError{ServerError: wrappedErr}
			}

			return dbscSessionResponseProcessor.Process(
				request.Context(),
				&dbsc_session_response_processor.Input{
					TokenString:      sessionResponseValue,
					DbscSessionId:    sessionToken.SessionId,
					AuthenticationId: sessionToken.AuthenticationId,
				},
			)
		},
	)

	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		// TODO: Check `amr` claim?
		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		sessionId := sessionToken.SessionId
		if sessionId == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("dbsc session id")),
			}
		}
		authenticationId := sessionToken.AuthenticationId
		if authenticationId == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication id")),
			}
		}

		publicKey, responseError := muxUtils.GetServerParsedRequestHeaders[[]byte](ctx)
		if responseError != nil {
			return nil, responseError
		}

		if len(publicKey) == 0 {
			challenge, err := session.GenerateDbscChallenge()
			if err != nil {
				return nil, &response_error.ResponseError{
					ServerError: fmt.Errorf("generate challenge: %w", err),
				}
			}

			insertDbCtx, insertDbCtxCancel := motmedelDatabase.MakeTimeoutCtx(ctx)
			defer insertDbCtxCancel()

			if err := database.InsertDbscChallenge(insertDbCtx, challenge, authenticationId, e.ChallengeDuration, db); err != nil {
				return nil, &response_error.ResponseError{
					ServerError: motmedelErrors.New(
						fmt.Errorf("insert dbsc challenge: %w", err),
						challenge, authenticationId,
					),
				}
			}

			return &muxResponse.Response{
				StatusCode: http.StatusUnauthorized,
				Headers: []*muxResponse.HeaderEntry{
					{
						Name:  "Sec-Session-Challenge",
						Value: fmt.Sprintf("\"%s\";id=\"%s\"", challenge, sessionId),
					},
				},
			}, nil
		}

		selectDbCtx, selectDbCtxCancel := motmedelDatabase.MakeTimeoutCtx(ctx)
		defer selectDbCtxCancel()

		authentication, err := database.SelectRefreshAuthentication(selectDbCtx, authenticationId, db)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(
					fmt.Errorf("get authentication: %w", err),
					authenticationId,
				),
			}
		}
		if authentication == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("authentication")),
			}
		}

		authenticationPublicKey := authentication.DbscPublicKey
		if len(authenticationPublicKey) == 0 {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("No public key for authentication."),
				),
			}
		}

		if !bytes.Equal(authenticationPublicKey, publicKey) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Public key mismatch."),
				),
				ClientError: mismatch_error.New("public key", publicKey, authenticationPublicKey),
			}
		}

		return sessionManager.RefreshSession(authentication, sessionToken, DbscAuthenticationMethod, e.SessionDuration)
	}

	e.Initialized = true

	return nil
}

func New(options ...dbsc_refresh_endpoint_config.Option) *Endpoint {
	config := dbsc_refresh_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   config.Path,
				Method: http.MethodPost,
			},
		},
		SessionDuration:   config.SessionDuration,
		ChallengeDuration: config.ChallengeDuration,
	}
}
