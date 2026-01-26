package end_endpoint

import (
	"context"
	"fmt"
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/end_endpoint/end_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

func (e *Endpoint) Initialize(
	authorizerRequestParser *authorizer_request_parser.Parser,
	endSession func(ctx context.Context, authenticationId string) error,
) error {
	if authorizerRequestParser == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("authorizer request parser"))
	}
	if endSession == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("end session"))
	}

	e.AuthenticationParser = adapter.New(authorizerRequestParser)
	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		authenticationId := sessionToken.AuthenticationId
		if authenticationId == "" {
			return nil, &muxResponseError.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication id")),
			}
		}

		// TODO: Make sure I do not delete authentications (for traceability) - what I want to do is mark them as ended.
		if err := endSession(ctx, authenticationId); err != nil {
			return nil, &muxResponseError.ResponseError{
				ServerError: motmedelErrors.New(fmt.Errorf("end session: %w", err), authenticationId),
			}
		}

		return &muxResponse.Response{
			Headers: []*muxResponse.HeaderEntry{{Name: "Clear-Site-Data", Value: `"cookies"`}},
		}, nil
	}

	e.Initialized = true

	return nil
}

func New(options ...end_endpoint_config.Option) *Endpoint {
	config := end_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   config.Path,
				Method: http.MethodPost,
			},
		},
	}
}
