package metadata

import (
	"context"
	"fmt"

	"github.com/Motmedel/utils_go/pkg/http/types/fetch_config"
	motmedelHttpUtils "github.com/Motmedel/utils_go/pkg/http/utils"
)

const metadataBaseUrlString = "http://metadata.google.internal/computeMetadata/v1"

func FetchProjectId(ctx context.Context, options ...fetch_config.Option) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context err: %w", err)
	}

	options = append(options, fetch_config.WithHeaders(map[string]string{"Metadata-Flavor": "Google"}))

	_, responseBody, err := motmedelHttpUtils.Fetch(
		ctx,
		metadataBaseUrlString+"/project/project-id",
		options...,
	)
	if err != nil {
		return "", fmt.Errorf("http utils fetch: %w", err)
	}

	return string(responseBody), nil
}
