package metadata

import (
	"github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelHttpUtils "github.com/Motmedel/utils_go/pkg/http/utils"
	"net/http"
)

const metadataBaseUrlString = "http://metadata.google.internal/computeMetadata/v1"

func GetProjectId(httpClient motmedelHttpUtils.HttpClient) (string, *motmedelHttpTypes.HttpContext, error) {
	if httpClient == nil {
		return "", nil, motmedelHttpErrors.ErrNilHttpClient
	}

	requestMethod := http.MethodGet
	requestUrl := metadataBaseUrlString + "/project/project-id"

	httpContext, err := motmedelHttpUtils.SendRequest(
		httpClient,
		requestMethod,
		requestUrl,
		nil,
		func(request *http.Request) error {
			if request == nil {
				return motmedelHttpErrors.ErrNilHttpRequest
			}

			requestHeader := request.Header
			if requestHeader == nil {
				return motmedelHttpErrors.ErrNilHttpRequestHeader
			}

			requestHeader.Set("Metadata-Flavor", "Google")

			return nil
		},
	)
	if err != nil {
		return "", httpContext, &errors.Error{
			Message: "An error occurred when sending the request.",
			Cause:   err,
			Input:   []any{requestMethod, requestUrl},
		}
	}
	if httpContext == nil {
		return "", nil, motmedelHttpErrors.ErrNilHttpContext
	}

	responseBody := httpContext.ResponseBody

	return string(responseBody), httpContext, nil
}
