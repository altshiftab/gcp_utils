package id_token_endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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
	motmedelJwt "github.com/Motmedel/utils_go/pkg/json/jose/jwt"
	authenticatorPkg "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/endpoint/id_token_endpoint/id_token_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/provider_claims"
)

type BodyInput struct {
	Token string `json:"token,omitempty" jsonschema:"token"`
}

var bodyInputParser *jsonSchemaBodyParser.Parser[*BodyInput]

type Endpoint[T provider_claims.ProviderClaims] struct {
	*initialization_endpoint.Endpoint
}

func (e *Endpoint[T]) Initialize(
	cseBodyParser *client_side_encryption.BodyParser,
	idTokenAuthenticator *authenticatorPkg.AuthenticatorWithKeyHandler,
	sessionManager *session_manager.Manager,
) error {
	if cseBodyParser == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("cse body parser"))
	}

	if idTokenAuthenticator == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("id token authenticator"))
	}

	if sessionManager == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager"))
	}

	bodyLoader := e.BodyLoader
	if bodyLoader == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("body loader"))
	}

	bodyLoader.Parser = adapter.New(
		body_parser.NewWithProcessor(
			cseBodyParser,
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
			// NOTE: Should be impossible. Should be covered by the jsonschema validation.
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(empty_error.New("id token")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The id token is empty."),
				),
			}
		}

		authenticatedIdToken, err := idTokenAuthenticator.Authenticate(ctx, idToken)
		if err != nil {
			wrappedErr := motmedelErrors.New(fmt.Errorf("authenticator with key handler authenticate: %w", err), idToken)
			if motmedelErrors.IsAny(err, motmedelErrors.ErrParseError, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("Invalid id token."),
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

		_, idTokenPayload, _, err := motmedelJwt.Parse(idToken)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("jwt parse: %w", err), idToken),
			}
		}
		if len(idTokenPayload) == 0 {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("id token payload")),
			}
		}

		var providerClaims T
		if err := json.Unmarshal(idTokenPayload, &providerClaims); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(
					fmt.Errorf("json unmarshal (id token payload): %w", err),
					idTokenPayload,
				),
			}
		}

		emailAddress, err := providerClaims.VerifiedEmailAddress()
		if err != nil {
			wrappedErr := motmedelErrors.New(
				fmt.Errorf("provider claims verified email address: %w", err),
				providerClaims,
			)
			if errors.Is(err, ssoErrors.ErrForbiddenUser) {
				return nil, &response_error.ResponseError{
					ProblemDetail: problem_detail.New(
						http.StatusForbidden,
						problem_detail_config.WithDetail("The email address that is tied to the id token is unverified or invalid."),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if emailAddress == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("email address")),
			}
		}

		response, responseError := sessionManager.CreateSession(ctx, strings.ToLower(emailAddress))
		if responseError != nil {
			return nil, responseError
		}
		if response == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("response")),
			}
		}

		return response, nil
	}

	e.Initialized = true
	return nil
}

func New[T provider_claims.ProviderClaims](path string, options ...id_token_endpoint_config.Option) (*Endpoint[T], error) {
	if path == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("path"))
	}

	return &Endpoint[T]{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   path,
				Method: http.MethodPost,
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
