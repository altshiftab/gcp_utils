package refresh_endpoint

import (
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	motmedelTimeErrors "github.com/Motmedel/utils_go/pkg/time/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/refresh_endpoint/refresh_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
)

const (
	RefreshAuthenticationMethod = "rtoken"
	DbscAuthenticationMethod    = "hwk"
	SsoAuthenticationMethod     = "ext"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	SessionDuration time.Duration
}

func (e *Endpoint) Initialize(
	authorizerRequestParser *authorizer_request_parser.Parser,
	sessionManager *session_manager.Manager,
	db *sql.DB,
) error {
	if authorizerRequestParser == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("authorizer request parser"))
	}

	if sessionManager == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager"))
	}

	if db == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("sql db"))
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
		return motmedelErrors.NewWithTrace(empty_error.New("token cookie name"))
	}

	e.AuthenticationParser = adapter.New(authorizerRequestParser)
	e.Handler = func(request *http.Request, bytes []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		authenticationId := sessionToken.AuthenticationId
		if authenticationId == "" {
			return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication id"))}
		}

		claims := sessionToken.Claims
		if claims == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("session token claims")),
			}
		}

		sessionExpiresAt := claims.ExpiresAt
		if sessionExpiresAt == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("session token claims expires at")),
			}
		}

		sessionNotBefore := claims.NotBefore
		if sessionNotBefore == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("session token claims not before")),
			}
		}

		// Don't refresh if the refresh is handled by the DBSC mechanism.
		if slices.Contains(claims.AuthenticationMethods, DbscAuthenticationMethod) {
			return nil, nil
		}

		authentication, err := database.SelectRefreshAuthentication(ctx, authenticationId, db)
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
		if slices.Contains(claims.AuthenticationMethods, SsoAuthenticationMethod) && len(authentication.DbscPublicKey) > 0 {
			return nil, nil
		}

		remainingExpirationDuration := time.Until(sessionExpiresAt.Time)
		if remainingExpirationDuration < 0 {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(http.StatusUnauthorized),
				ClientError:   motmedelErrors.NewWithTrace(motmedelTimeErrors.ErrNegativeDuration),
			}
		}

		// The session token should be refreshed if one third or less of its expiration duration remains.
		if remainingExpirationDuration > (sessionExpiresAt.Sub(sessionNotBefore.Time) / 3) {
			return nil, nil
		}

		return sessionManager.RefreshSession(authentication, sessionToken, RefreshAuthenticationMethod, e.SessionDuration)
	}

	e.Initialized = true

	return nil
}

func New(options ...refresh_endpoint_config.Option) *Endpoint {
	config := refresh_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   config.Path,
				Method: http.MethodPost,
			},
		},
		SessionDuration: config.SessionDuration,
	}
}
