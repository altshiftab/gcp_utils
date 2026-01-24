package refresh_request_parser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	motmedelMuxErrors "github.com/Motmedel/utils_go/pkg/http/mux/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/header_extractor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/parsed_input"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/session_response_processor"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/session_response_processor/session_response_processor_config"
)

const (
	sessionResponseHeaderName = "Sec-Session-Response"
	sessionIdHeaderName       = "Sec-Session-Id"
)

var sessionIdRequestParser = &header_extractor.Parser{Name: sessionIdHeaderName}

type RequestParser struct {
	processor *session_response_processor.Processor
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

	dbscSessionId, responseError := sessionIdRequestParser.Parse(request)
	if responseError != nil {
		return nil, responseError
	}

	authenticationId, _, found := strings.Cut(dbscSessionId, ":")
	if !found {
		return nil, &response_error.ResponseError{
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				fmt.Sprintf("Malformed %s header.", sessionIdHeaderName),
				nil,
			),
			ClientError: motmedelErrors.NewWithTrace(
				fmt.Errorf("%w (dbsc session id)", motmedelErrors.ErrBadSplit),
				dbscSessionId,
			),
		}
	}

	parsedInput := &parsed_input.Input{DbscSessionId: dbscSessionId, AuthenticationId: authenticationId}

	sessionResponseValue, err := utils.GetSingleHeader(sessionResponseHeaderName, requestHeader)
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("get single header: %w", err))
		if errors.Is(err, motmedelHttpErrors.ErrMissingHeader) {
			return parsedInput, nil
		} else if errors.Is(err, motmedelHttpErrors.ErrMultipleHeaderValues) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
					"Multiple header values.",
					map[string]string{"header": sessionResponseHeaderName},
				),
			}
		}

		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}

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

	parsedInput.Output = output

	return parsedInput, nil
}

func New(
	audience string,
	checkChallenge func(ctx context.Context, challenge string, authenticationId string) (userId string, err error),
	options ...session_response_processor_config.Option,
) (*RequestParser, error) {
	processor, err := session_response_processor.New(audience, checkChallenge, options...)
	if err != nil {
		return nil, fmt.Errorf("session response processor new: %w", err)
	}

	return &RequestParser{processor: processor}, nil
}
