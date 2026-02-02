package refresh_endpoint

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/cors_configurator"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	motmedelTimeErrors "github.com/Motmedel/utils_go/pkg/time/errors"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/authentication"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authentication_method"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/refresh_endpoint/refresh_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	SessionDuration             time.Duration
	selectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)
}

func (e *Endpoint) Initialize(
	authorizerRequestParser *authorizer_request_parser.Parser,
	corsConfigurator *cors_configurator.Configurator,
	sessionManager *session_manager.Manager,
) error {
	if authorizerRequestParser == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("authorizer request parser"))
	}

	if corsConfigurator == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("cors configurator"))
	}

	if sessionManager == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager"))
	}

	db := sessionManager.Db
	if db == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager sql db"))
	}

	jwtExtractor := authorizerRequestParser.JwtExtractor
	if jwtExtractor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("authentication parser jwt extractor"))
	}

	tokenExtractor := jwtExtractor.TokenExtractor
	if tokenExtractor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("authentication parser jwt extractor token extractor"))
	}

	cookieName := tokenExtractor.Name
	if cookieName == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("authentication parser jwt extractor token extractor name"))
	}

	e.AuthenticationParser = adapter.New(authorizerRequestParser)

	e.CorsParser = corsConfigurator

	e.Handler = func(request *http.Request, bytes []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		authenticationId := sessionToken.AuthenticationId
		if authenticationId == "" {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(empty_error.New("authentication id")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session token authentication id is empty."),
				),
			}
		}

		claims := sessionToken.Claims
		if claims == nil {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(nil_error.New("session token claims")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session token claims are empty."),
				),
			}
		}

		sessionExpiresAt := claims.ExpiresAt
		if sessionExpiresAt == nil {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(nil_error.New("session token claims expires at")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session token expires at is empty."),
				),
			}
		}

		sessionNotBefore := claims.NotBefore
		if sessionNotBefore == nil {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(nil_error.New("session token claims not before")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session token not before is empty."),
				),
			}
		}

		// Don't refresh if the refresh is handled by the DBSC mechanism.
		if slices.Contains(claims.AuthenticationMethods, authentication_method.Dbsc) {
			return nil, nil
		}

		authentication, err := e.selectRefreshAuthentication(ctx, authenticationId, db)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(fmt.Errorf("get authentication: %w", err), authenticationId),
			}
		}
		if authentication == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("authentication")),
			}
		}

		// Don't refresh if this is the first session and DBSC has been added.
		if slices.Contains(claims.AuthenticationMethods, authentication_method.Sso) && len(authentication.DbscPublicKey) > 0 {
			return nil, nil
		}

		remainingExpirationDuration := time.Until(sessionExpiresAt.Time)
		if remainingExpirationDuration < 0 {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(motmedelTimeErrors.ErrNegativeDuration),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The expiration duration is negative, indicating an invalid session token."),
				),
			}
		}

		// The session token should be refreshed if one third or less of its expiration duration remains.
		if remainingExpirationDuration > (sessionExpiresAt.Sub(sessionNotBefore.Time) / 3) {
			return nil, nil
		}

		return sessionManager.RefreshSession(authentication, sessionToken, authentication_method.Refresh, e.SessionDuration)
	}

	e.Initialized = true

	return nil
}

func New(options ...refresh_endpoint_config.Option) *Endpoint {
	config := refresh_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:       config.Path,
				Method:     http.MethodPost,
				BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
			},
		},
		SessionDuration:             config.SessionDuration,
		selectRefreshAuthentication: config.SelectRefreshAuthentication,
	}
}
