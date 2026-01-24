package register_request_parser

import (
	"context"
	"fmt"
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	motmedelMuxErrors "github.com/Motmedel/utils_go/pkg/http/mux/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/header_extractor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/parsed_input"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/session_response_processor"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/session_response_processor/session_response_processor_config"
	sessionErrors "github.com/altshiftab/gcp_utils/pkg/http/login/session/errors"
)

const (
	sessionResponseHeaderName = "Sec-Session-Response"
)

var sessionResponseRequestParser = &header_extractor.Parser{Name: sessionResponseHeaderName}

type RequestParser struct {
	SessionRequestParser request_parser.RequestParser[session.SessionInput]
	processor            *session_response_processor.Processor
}

func (p *RequestParser) Parse(request *http.Request) (*parsed_input.Input, *response_error.ResponseError) {
	processor := p.processor
	if processor == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(motmedelMuxErrors.ErrNilProcessor),
		}
	}

	if request == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequest),
		}
	}

	requestHeader := request.Header
	if requestHeader == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequestHeader),
		}
	}

	sessionResponseValue, responseError := sessionResponseRequestParser.Parse(request)
	if responseError != nil {
		return nil, responseError
	}

	sessionInput, responseError := p.SessionRequestParser.Parse(request)
	if responseError != nil {
		return nil, responseError
	}
	if utils.IsNil(sessionInput) {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(sessionErrors.ErrNilSessionInput),
		}
	}

	dbscSessionId := sessionInput.GetId()
	authenticationId := sessionInput.GetAuthenticationId()

	output, responseError := processor.Process(
		request.Context(),
		&session_response_processor.Input{
			TokenString:      sessionResponseValue,
			DbscSessionId:    dbscSessionId,
			AuthenticationId: authenticationId,
		},
	)
	if responseError != nil {
		return nil, responseError
	}

	return &parsed_input.Input{DbscSessionId: dbscSessionId, AuthenticationId: authenticationId, Output: output}, nil
}

func New(
	audience string,
	checkChallenge func(ctx context.Context, challenge string, authenticationId string) (userId string, err error),
	sessionRequestParser request_parser.RequestParser[session.SessionInput],
	options ...session_response_processor_config.Option,
) (*RequestParser, error) {
	if utils.IsNil(sessionRequestParser) {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("%w (session)", motmedelMuxErrors.ErrNilRequestParser))
	}

	processor, err := session_response_processor.New(audience, checkChallenge, options...)
	if err != nil {
		return nil, fmt.Errorf("session response processor new: %w", err)
	}

	return &RequestParser{SessionRequestParser: sessionRequestParser, processor: processor}, nil
}
