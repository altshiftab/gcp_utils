package metadata

import (
	"context"
	"fmt"
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelHttpUtils "github.com/Motmedel/utils_go/pkg/http/utils"
)

const metadataBaseUrlString = "http://metadata.google.internal/computeMetadata/v1"

func GetProjectId(ctx context.Context, httpClient *http.Client) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context err: %w", err)
	}

	if httpClient == nil {
		return "", motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpClient)
	}

	_, responseBody, err := motmedelHttpUtils.Fetch(
		ctx,
		metadataBaseUrlString+"/project/project-id",
		httpClient,
		&motmedelHttpTypes.FetchOptions{
			Headers: map[string]string{"Metadata-Flavor": "Google"},
		},
	)
	if err != nil {
		return "", fmt.Errorf("http utils fetch: %w", err)
	}

	return string(responseBody), nil
}
