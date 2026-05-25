package generate_endpoint

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader/body_setting"
	bodyParserAdapter "github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser/json_body_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/numeric_date"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	motmedelMail "github.com/Motmedel/utils_go/pkg/mail"
	"github.com/Motmedel/utils_go/pkg/mail/types/message"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/magic_link/types/endpoint/generate_endpoint/generate_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/magic_link/types/mail_sender"
)

type BodyInput struct {
	EmailAddress string `json:"email_address" jsonschema:"email_address,format:email"`
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
	LinkExpiration time.Duration
	Subject        string
	messageBuilder generate_endpoint_config.MessageBuilder
	makeNonce      func() string
}

func (e *Endpoint) Initialize(
	mailSender mail_sender.Sender,
	signer motmedelCryptoInterfaces.NamedSigner,
	fromAddress *mail.Address,
	linkBaseUrl *url.URL,
) error {
	if utils.IsNil(mailSender) {
		return motmedelErrors.NewWithTrace(nil_error.New("mail sender"))
	}

	if utils.IsNil(signer) {
		return motmedelErrors.NewWithTrace(nil_error.New("signer"))
	}

	if fromAddress == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("from address"))
	}

	if linkBaseUrl == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("link base url"))
	}

	if e.messageBuilder == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("message builder"))
	}

	if e.makeNonce == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("make nonce"))
	}

	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		body, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*BodyInput](ctx)
		if responseError != nil {
			return nil, responseError
		}

		emailAddress := strings.ToLower(strings.TrimSpace(body.EmailAddress))
		if emailAddress == "" {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusUnprocessableEntity,
					problem_detail_config.WithDetail("The email address is empty."),
				),
			}
		}

		if err := motmedelMail.ValidateAddress(emailAddress); err != nil {
			if errors.Is(err, motmedelErrors.ErrValidationError) {
				return nil, &response_error.ResponseError{
					ClientError: motmedelErrors.New(fmt.Errorf("validate address: %w", err), emailAddress),
					ProblemDetail: problem_detail.New(
						http.StatusUnprocessableEntity,
						problem_detail_config.WithDetail("The email address is invalid."),
					),
				}
			}
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(fmt.Errorf("validate address: %w", err), emailAddress),
			}
		}

		toAddress := &mail.Address{Address: emailAddress}

		nonce := e.makeNonce()
		if nonce == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("nonce")),
			}
		}

		now := time.Now()
		expiresAt := now.Add(e.LinkExpiration)

		claims := &registered_claims.Claims{
			Id:        nonce,
			Subject:   emailAddress,
			IssuedAt:  numeric_date.New(now),
			ExpiresAt: numeric_date.New(expiresAt),
		}
		claimsData, err := json.Marshal(claims)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("json marshal (claims): %w", err)),
			}
		}
		var payload map[string]any
		if err := json.Unmarshal(claimsData, &payload); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("json unmarshal (claims data): %w", err), claimsData),
			}
		}

		token := &motmedelJwtToken.Token{Payload: payload}
		tokenString, err := token.Encode(signer)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("token encode: %w", err)),
			}
		}

		linkUrl := *linkBaseUrl
		query := linkUrl.Query()
		query.Set("token", tokenString)
		linkUrl.RawQuery = query.Encode()

		messageBody, err := e.messageBuilder(toAddress, &linkUrl, expiresAt)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("message builder: %w", err)),
			}
		}
		if messageBody == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("message body")),
			}
		}

		msg, err := message.New(fromAddress, []*mail.Address{toAddress}, e.Subject, messageBody)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("message new: %w", err)),
			}
		}

		if err := mailSender.SendMessage(ctx, msg); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("mail sender send message: %w", err)),
			}
		}

		return nil, nil
	}

	e.Initialized = true

	return nil
}

func New(options ...generate_endpoint_config.Option) *Endpoint {
	config := generate_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   config.Path,
				Method: http.MethodPost,
				Public: true,
				BodyLoader: &body_loader.Loader{
					Setting:     body_setting.Required,
					ContentType: "application/json",
					MaxBytes:    config.MaxBytes,
					Parser:      bodyParserAdapter.New(json_body_parser.New[*BodyInput]()),
				},
				Hint: &endpoint.Hint{
					InputType: motmedelReflect.TypeOf[BodyInput](),
				},
			},
		},
		LinkExpiration: config.LinkExpiration,
		Subject:        config.Subject,
		messageBuilder: config.MessageBuilder,
		makeNonce:      config.MakeNonce,
	}
}
