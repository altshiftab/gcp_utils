package login_endpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/url_allower"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/url_allower/url_allower_config"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/database/oauth_flow"
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/endpoint/login_endpoint/login_endpoint_config"
	"golang.org/x/oauth2"
)

func makeCodeVerifier() (string, error) {
	challenge := make([]byte, 96)
	if _, err := rand.Read(challenge); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return base64.RawURLEncoding.EncodeToString(challenge), nil
}

func makeState() (string, error) {
	state := make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(state), nil
}

type UrlInput struct {
	RedirectUrl string `json:"redirect"`
}

func (u *UrlInput) URL() string {
	return u.RedirectUrl
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
	CallbackCookieDuration time.Duration
	CallbackCookieName     string
	CallbackPath           string
}

func (e *Endpoint) Initialize(
	domain string,
	oauthConfig *oauth2.Config,
	addOauthFlow func(ctx context.Context, oauthFlow *oauth_flow.Flow) (string, error),
) error {
	if domain == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("domain"))
	}

	if oauthConfig == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("oauth config"))
	}

	if addOauthFlow == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("add oauth flow"))
	}

	e.UrlParser = adapter.New(
		url_allower.New(
			query_extractor.New[*UrlInput](),
			url_allower_config.WithAllowLocalhost(domain == "localhost"),
			url_allower_config.WithAllowedDomains([]string{domain}),
		),
	)

	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		redirectUrl, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*url.URL](ctx)
		if responseError != nil {
			return nil, responseError
		}

		codeVerifier, err := makeCodeVerifier()
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("make code verifier: %w", err)),
			}
		}
		if codeVerifier == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("code verifier")),
			}
		}

		state, err := makeState()
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("make state: %w", err)),
			}
		}
		if state == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("state")),
			}
		}

		oauthFlow := &oauth_flow.Flow{State: state, CodeVerifier: codeVerifier, RedirectUrl: redirectUrl.String()}
		oauthFlowId, err := addOauthFlow(ctx, oauthFlow)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(fmt.Errorf("add oauth flow: %w", err), oauthFlow),
			}
		}
		if oauthFlowId == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("oauth flow id")),
			}
		}

		callbackCookie := http.Cookie{
			Name:     e.CallbackCookieName,
			Value:    oauthFlowId,
			Path:     e.CallbackPath,
			Expires:  time.Now().Add(e.CallbackCookieDuration),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}

		return &muxResponse.Response{
			StatusCode: http.StatusFound,
			Headers: []*muxResponse.HeaderEntry{
				{
					Name:  "Set-Cookie",
					Value: callbackCookie.String(),
				},
				{
					Name:  "Location",
					Value: oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier)),
				},
			},
		}, nil
	}

	e.Initialized = true

	return nil
}

func New(path, callbackPath string, options ...login_endpoint_config.Option) (*Endpoint, error) {
	if path == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("path"))
	}

	if callbackPath == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("callback path"))
	}

	// TODO: Add hint?
	config := login_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   path,
				Method: http.MethodGet,
				Public: true,
			},
		},
		CallbackCookieName:     config.CallbackCookieName,
		CallbackCookieDuration: config.CallbackCookieDuration,
		CallbackPath:           callbackPath,
	}, nil
}
