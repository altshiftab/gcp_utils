package dbsc_register_endpoint

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	motmedelDatabase "github.com/Motmedel/utils_go/pkg/database"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/header_extractor"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/dbsc_session_response_processor"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_cookie"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
)

// Use centralized DBSC header constants from the session package.
const (
	sessionResponseHeaderName = session.DbscSessionResponseHeaderName
)

type Scope struct {
	Origin        string `json:"origin,omitempty"`
	IncludeSite   bool   `json:"include_site,omitempty"`
	DeferRequests bool   `json:"defer_requests,omitempty"`
}

type Credential struct {
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	Attributes string `json:"attributes,omitempty"`
}

type Response struct {
	SessionIdentifier string        `json:"session_identifier"`
	RefreshURL        string        `json:"refresh_url"`
	Scope             Scope         `json:"scope"`
	Credentials       []*Credential `json:"credentials"`
}

var sessionResponseRequestParser *header_extractor.Parser

type Endpoint struct {
	*initialization_endpoint.Endpoint
	RefreshPath                           string
	updateAuthenticationWithDbscPublicKey func(ctx context.Context, id string, key []byte, database *sql.DB) error
}

func (e *Endpoint) Initialize(
	authorizerRequestParser *authorizer_request_parser.Parser,
	dbscSessionResponseProcessor *dbsc_session_response_processor.Processor,
	registeredDomain string,
) error {
	if authorizerRequestParser == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("authorizer request parser"))
	}

	jwtExtractor := authorizerRequestParser.JwtExtractor
	if jwtExtractor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("jwt extractor"))
	}

	tokenExtractor := jwtExtractor.TokenExtractor
	if tokenExtractor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("jwt token extractor"))
	}

	cookieName := tokenExtractor.Name
	if cookieName == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("cookie name"))
	}

	if dbscSessionResponseProcessor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("dbsc session response processor"))
	}

	db := dbscSessionResponseProcessor.Db
	if db == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("dbsc session response processor sql db"))
	}

	e.AuthenticationParser = adapter.New(authorizerRequestParser)
	e.HeaderParser = request_parser.New(
		func(request *http.Request) (any, *response_error.ResponseError) {
			ctx := request.Context()
			sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
			if responseError != nil {
				return nil, responseError
			}

			sessionResponseValue, responseError := sessionResponseRequestParser.Parse(request)
			if responseError != nil {
				return nil, responseError
			}

			return dbscSessionResponseProcessor.Process(
				ctx,
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

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
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
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(empty_error.New("public key")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The public key is empty."),
				),
			}
		}

		dbCtx, dbCtxCancel := motmedelDatabase.MakeTimeoutCtx(ctx)
		defer dbCtxCancel()
		if err := e.updateAuthenticationWithDbscPublicKey(dbCtx, authenticationId, publicKey, db); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(
					fmt.Errorf("set authentication public key: %w", err),
					authenticationId, publicKey,
				),
			}
		}

		response := Response{
			SessionIdentifier: authenticationId,
			RefreshURL:        e.RefreshPath,
			Scope: Scope{
				Origin:      fmt.Sprintf("https://%s", registeredDomain),
				IncludeSite: true,
			},
			Credentials: []*Credential{
				{
					Type:       "cookie",
					Name:       cookieName,
					Attributes: session_cookie.Attributes(registeredDomain),
				},
			},
		}

		responseData, err := json.Marshal(response)
		if err != nil {
			return nil, &response_error.ResponseError{
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

	e.Initialized = true

	return nil
}

func New(options ...dbsc_register_endpoint_config.Option) *Endpoint {
	config := dbsc_register_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   config.Path,
				Method: http.MethodPost,
			},
		},
		RefreshPath:                           config.RefreshPath,
		updateAuthenticationWithDbscPublicKey: config.UpdateAuthenticationWithDbscPublicKey,
	}
}

func init() {
	var err error
	sessionResponseRequestParser, err = header_extractor.New(sessionResponseHeaderName)
	if err != nil {
		panic(fmt.Errorf("header extractor new (session response): %w", err))
	}
}
