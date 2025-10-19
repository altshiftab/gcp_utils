package sso

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
)

var (
	ErrUnexpectedUrlQueryParameter = errors.New("unexpected url query parameter")
	ErrEmptyQueryParameterValues   = errors.New("empty query parameter values")
	ErrDuplicateQueryParameter     = errors.New("duplicate query parameter")
	ErrEmptyState                  = errors.New("empty state")
	ErrEmptyCode                   = errors.New("empty code")
	ErrNilIdToken                  = errors.New("nil id token")
)

type CallbackUrlInput struct {
	State        string
	Code         string
	Scopes       []string
	AuthUser     int
	HostedDomain string
	Prompt       string
}

func MakeCodeVerifier() (string, error) {
	challenge := make([]byte, 96)
	if _, err := rand.Read(challenge); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return base64.RawURLEncoding.EncodeToString(challenge), nil
}

func getUrlInput(name string, values []string) (string, *muxResponseError.ResponseError) {
	if len(values) == 0 {
		return "", &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				fmt.Sprintf("Empty query parameter values: %q.", name),
				nil,
			),
			ClientError: fmt.Errorf("%w: %s", ErrEmptyQueryParameterValues, name),
		}
	}

	if len(values) > 1 {
		return "", &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				fmt.Sprintf("Duplicate query parameter: %q.", name),
				nil,
			),
			ClientError: fmt.Errorf("%w: %s", ErrDuplicateQueryParameter, name),
		}
	}

	return values[0], nil
}

func CallbackUrlParser(request *http.Request) (any, *muxResponseError.ResponseError) {
	if request == nil {
		return nil, &muxResponseError.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequest),
		}
	}

	requestUrl := request.URL
	if requestUrl == nil {
		return nil, &muxResponseError.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequestUrl),
		}
	}

	rawQuery := requestUrl.RawQuery
	queryValues, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, &muxResponseError.ResponseError{
			ClientError: motmedelErrors.NewWithTrace(
				fmt.Errorf("url parse query: %w", err),
				rawQuery,
			),
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				"Invalid query string.",
				nil,
			),
		}
	}

	// TODO: put in separate function?

	var urlInput CallbackUrlInput

	for key, values := range queryValues {
		switch key {
		case "state", "code", "scope", "authuser", "hd", "prompt":
			if value, responseError := getUrlInput(key, values); responseError != nil {
				return nil, responseError
			} else {
				switch key {
				case "state":
					urlInput.State = value
				case "code":
					urlInput.Code = value
				case "scope":
					urlInput.Scopes = strings.Split(value, " ")
				case "authuser":
					authUser, err := strconv.Atoi(value)
					if err != nil {
						return nil, &muxResponseError.ResponseError{
							ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
								fmt.Sprintf("Invalid authuser: %q.", value),
								nil,
							),
							ClientError: motmedelErrors.NewWithTrace(fmt.Errorf("strvconv atoi (authuser): %w", err)),
						}
					}
					urlInput.AuthUser = authUser
				case "hd":
					urlInput.HostedDomain = value
				case "prompt":
					urlInput.Prompt = value
				default:
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("%w: %s", ErrUnexpectedUrlQueryParameter, key),
							key,
						),
					}
				}
			}
		default:
			return nil, &muxResponseError.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(
					fmt.Errorf("%w: %s", ErrUnexpectedUrlQueryParameter, key),
					key,
				),
			}
		}
	}

	if urlInput.Code == "" {
		return nil, &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				"No code provided.",
				nil,
			),
			ClientError: motmedelErrors.NewWithTrace(ErrEmptyCode),
		}
	}

	if urlInput.State == "" {
		return nil, &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				"No state provided.",
				nil,
			),
			ClientError: motmedelErrors.NewWithTrace(ErrEmptyState),
		}
	}

	return &urlInput, nil
}