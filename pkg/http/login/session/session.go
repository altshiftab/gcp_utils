package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux"
	muxErrors "github.com/Motmedel/utils_go/pkg/http/mux/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/parsing"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	"github.com/Motmedel/utils_go/pkg/utils"
	loginServiceErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
)

const (
	refreshEndpoint = "/api/session/refresh"
)

func checkOrigin(origin string, registeredDomain string) *muxResponseError.ResponseError {
	if registeredDomain == "" {
		return &muxResponseError.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(loginServiceErrors.ErrEmptyRegisteredDomain),
		}
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return &muxResponseError.ResponseError{
			ClientError: motmedelErrors.NewWithTrace(fmt.Errorf("url parse (origin): %w", err), origin),
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				"Invalid Origin header.",
				nil,
			),
		}
	}

	originHostname := parsedOrigin.Hostname()
	originDomainBreakdown := domain_breakdown.GetDomainBreakdown(originHostname)
	if originDomainBreakdown == nil {
		return &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				"Invalid Origin header hostname.",
				nil,
			),
		}
	}

	if originDomainBreakdown.RegisteredDomain != registeredDomain {
		return &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
				http.StatusForbidden,
				"The origin registered domain does not match the registered domain.",
				nil,
			),
		}
	}

	return nil
}

type SessionInput interface {
	GetAuthenticationId() string
	UsesDbsc() bool
	IsFirstSession() bool
	GetExpiresAt() time.Time
	GetNotBefore() time.Time
	GetUserId() string
}

type SessionHandler interface {
	GetAuthenticationPublicKey(ctx context.Context, authenticationId string) ([]byte, error)
	MakeSessionSetCookie(ctx context.Context, authenticationId string, userId string, sessionType string) (*muxResponse.HeaderEntry, error)
	EndSession(ctx context.Context, authenticationId string) error
	GetSessionRequestParser() request_parser.RequestParser[SessionInput]
}

func PatchMux(
	mux *mux.Mux,
	sessionHandler SessionHandler,
	registeredDomain string,
) error {
	if utils.IsNil(sessionHandler) {
		return motmedelErrors.NewWithTrace(loginServiceErrors.ErrNilSessionHandler)
	}

	if mux == nil {
		return nil
	}

	if registeredDomain == "" {
		return motmedelErrors.NewWithTrace(loginServiceErrors.ErrEmptyRegisteredDomain)
	}

	sessionRequestParser := sessionHandler.GetSessionRequestParser()
	if utils.IsNil(sessionRequestParser) {
		return motmedelErrors.NewWithTrace(muxErrors.ErrNilRequestParser)
	}

	headerParser := adapter.New(sessionHandler.GetSessionRequestParser())

	mux.Add(
		&endpoint_specification.EndpointSpecification{
			Path:                      refreshEndpoint,
			Method:                    http.MethodPost,
			HeaderParserConfiguration: &parsing.HeaderParserConfiguration{Parser: headerParser},
			Handler: func(request *http.Request, bytes []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				if request == nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequest),
					}
				}

				requestHeader := request.Header
				if requestHeader == nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequestHeader),
					}
				}

				var headerEntries []*muxResponse.HeaderEntry

				if _, ok := requestHeader["Origin"]; ok {
					origin := requestHeader.Get("Origin")

					if responseError := checkOrigin(origin, registeredDomain); responseError != nil {
						return nil, responseError
					}

					headerEntries = append(
						headerEntries,
						&muxResponse.HeaderEntry{Name: "Access-Control-Allow-Origin", Value: origin},
						&muxResponse.HeaderEntry{Name: "Access-Control-Allow-Credentials", Value: "true"},
					)
				}

				sessionInput, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[SessionInput](ctx)
				if responseError != nil {
					responseError.Headers = append(responseError.Headers, headerEntries...)
					return nil, responseError
				}

				if sessionInput.UsesDbsc() {
					// Session refresh is handled by the DBSC mechanism. Done here.
					return &muxResponse.Response{Headers: headerEntries}, nil
				}

				// Don't refresh if this is the first session and DBSC has been added.
				authenticationId := sessionInput.GetAuthenticationId()
				if sessionInput.IsFirstSession() {
					publicKey, err := sessionHandler.GetAuthenticationPublicKey(ctx, authenticationId)
					if err != nil {
						wrappedErr := motmedelErrors.New(
							fmt.Errorf("session handler get authentication public key: %w", err),
							authenticationId,
						)
						if errors.Is(err, loginServiceErrors.ErrNoAuthenticationPublicKey) {
							return nil, &muxResponseError.ResponseError{
								ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
									http.StatusUnauthorized,
									"The session's authentication no longer exists.",
									nil,
								),
								ServerError: wrappedErr,
							}
						}

						return nil, &muxResponseError.ResponseError{
							ServerError: wrappedErr,
							Headers:     headerEntries,
						}
					}

					if len(publicKey) != 0 {
						// Session refresh is handled by the DBSC mechanism. Done here.
						return &muxResponse.Response{Headers: headerEntries}, nil
					}
				}

				sessionExpiresAt := sessionInput.GetExpiresAt()
				remainingExpirationDuration := time.Until(sessionExpiresAt)
				if remainingExpirationDuration < 0 {
					return nil, &muxResponseError.ResponseError{
						ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
							http.StatusUnauthorized,
							"",
							nil,
						),
						ClientError: motmedelErrors.NewWithTrace(loginServiceErrors.ErrNegativeDuration),
					}
				}

				// The session token should be refreshed if one third or less of its expiration duration remains.
				if remainingExpirationDuration > (sessionExpiresAt.Sub(sessionInput.GetNotBefore()) / 3) {
					return &muxResponse.Response{Headers: headerEntries}, nil
				}

				userId := sessionInput.GetUserId()

				headerEntry, err := sessionHandler.MakeSessionSetCookie(ctx, authenticationId, userId, "refresh")
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("session handler make header: %w", err),
							authenticationId, userId,
						),
						Headers: headerEntries,
					}
				}
				if headerEntry == nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(loginServiceErrors.ErrNilSessionCookieHeaderEntry),
						Headers:     headerEntries,
					}
				}

				headerEntries = append(headerEntries, headerEntry)

				return &muxResponse.Response{Headers: headerEntries}, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   refreshEndpoint,
			Method: http.MethodOptions,
			Handler: func(request *http.Request, body []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				if request == nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequest),
					}
				}

				requestHeader := request.Header
				if requestHeader == nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequestHeader),
					}
				}

				if _, ok := requestHeader["Origin"]; !ok {
					return nil, &muxResponseError.ResponseError{
						ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
							"Missing Origin header.",
							nil,
						),
					}
				}

				origin := requestHeader.Get("Origin")
				if origin == "" {
					return nil, &muxResponseError.ResponseError{
						ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
							"Empty Origin header.",
							nil,
						),
					}
				}

				if responseError := checkOrigin(origin, registeredDomain); responseError != nil {
					return nil, responseError
				}

				return &muxResponse.Response{
					Headers: []*muxResponse.HeaderEntry{
						{Name: "Access-Control-Allow-Origin", Value: origin},
						{Name: "Access-Control-Allow-Credentials", Value: "true"},
						{Name: "Access-Control-Allow-Methods", Value: "POST, OPTIONS"},
					},
				}, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:                      "/api/session/end",
			Method:                    http.MethodPost,
			HeaderParserConfiguration: &parsing.HeaderParserConfiguration{Parser: headerParser},
			Handler: func(request *http.Request, bytes []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				sessionInput, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[SessionInput](ctx)
				if responseError != nil {
					return nil, responseError
				}

				authenticationId := sessionInput.GetAuthenticationId()
				if err := sessionHandler.EndSession(ctx, authenticationId); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("session handler end session: %w", err),
							sessionHandler, authenticationId,
						),
					}
				}

				return &muxResponse.Response{
					Headers: []*muxResponse.HeaderEntry{{Name: "Clear-Site-Data", Value: `"cookies"`}},
				}, nil
			},
		},
	)

	return nil
}
