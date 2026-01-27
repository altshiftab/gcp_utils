package id_token_endpoint

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser/adapter"
	jsonSchemaBodyParser "github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser/json_schema_body_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/processor"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/mux/utils/client_side_encryption"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	authenticatorPkg "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token/authenticated_token"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/session/types/database/authentication"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/cse_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/endpoint/id_token_endpoint/id_token_endpoint_config"
)

type BodyInput struct {
	Token string `json:"token,omitempty" jsonschema:"token"`
}

var bodyInputParser *jsonSchemaBodyParser.Parser[*BodyInput]

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

func (e *Endpoint) Initialize(
	cseConfig *cse_config.Config,
	idTokenAuthenticator *authenticatorPkg.AuthenticatorWithKeyHandler,
	handleAuthenticatedIdToken func(context.Context, *authenticated_token.Token) (*authenticationPkg.Authentication, error),
) error {
	if cseConfig == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("cse config"))
	}

	if idTokenAuthenticator == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("id token authenticator"))
	}

	if handleAuthenticatedIdToken == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("handle authenticated id token"))
	}

	bodyLoader := e.BodyLoader
	if bodyLoader == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("body loader"))
	}

	bodyLoader.Parser = adapter.New(
		body_parser.NewWithProcessor(
			&client_side_encryption.BodyParser{
				PrivateKey:        cseConfig.PrivateKey,
				KeyAlgorithm:      cseConfig.KeyAlgorithm,
				ContentEncryption: cseConfig.ContentEncryption,
			},
			processor.New(
				func(ctx context.Context, decryptedPayload []byte) (*BodyInput, *response_error.ResponseError) {
					tokenInput, responseError := bodyInputParser.Parse(nil, decryptedPayload)
					if responseError != nil {
						return nil, responseError
					}
					return tokenInput, nil
				},
			),
		),
	)

	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		idTokenInput, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*BodyInput](ctx)
		if responseError != nil {
			return nil, responseError
		}

		idToken := idTokenInput.Token
		if idToken == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("id token")),
			}
		}
		authenticatedIdToken, err := idTokenAuthenticator.Authenticate(ctx, idToken)
		if err != nil {
			wrappedErr := motmedelErrors.New(fmt.Errorf("authenticator authenticate: %w", err), idToken)
			if motmedelErrors.IsAny(err, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("The id token could not be authenticated."),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if authenticatedIdToken == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("authenticated id token")),
			}
		}

		authentication, err := handleAuthenticatedIdToken(ctx, authenticatedIdToken)
		if err != nil {
			if errors.Is(err, ssoErrors.ErrForbiddenUser) {
				return nil, &response_error.ResponseError{
					ClientError:   err,
					ProblemDetail: problem_detail.New(http.StatusForbidden),
				}
			}
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(fmt.Errorf("handle authenticated id token: %w", err)),
			}
		}
		if authentication == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("authentication")),
			}
		}

		// TODO: Use "session manager" to create a session

		return nil, nil
	}

	e.Initialized = true
	return nil
}

func New(path string, options ...id_token_endpoint_config.Option) (*Endpoint, error) {
	if path == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("path"))
	}

	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path: path,
				BodyLoader: &body_loader.Loader{
					ContentType: "application/jose",
					MaxBytes:    4096,
				},
				Public: true,
				Hint: &endpoint.Hint{
					InputType: motmedelReflect.TypeOf[*BodyInput](),
				},
			},
		},
	}, nil
}

func init() {
	var err error
	bodyInputParser, err = jsonSchemaBodyParser.New[*BodyInput]()
	if err != nil {
		panic(fmt.Sprintf("json schema body parser new (id token body input): %v", err))
	}
}
