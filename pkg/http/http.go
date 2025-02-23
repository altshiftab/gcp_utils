package http

import (
	"context"
	motmedelMux "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTypesEndpointSpecification "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	altshiftGcpUtilsEnv "github.com/altshiftab/gcp_utils/pkg/env"
	"log/slog"
)

func PatchMux(mux *motmedelMux.Mux) {
	if mux == nil {
		return
	}

	if altshiftGcpUtilsEnv.GetLogLevelWithDefault() == "DEBUG" {
		mux.DoneCallback = func(ctx context.Context) {
			slog.DebugContext(ctx, "An HTTP response was served.")
		}
	}
}

func MakeMux(
	specifications []*muxTypesEndpointSpecification.EndpointSpecification,
	contextKeyValuePairs [][2]any,
) *motmedelMux.Mux {
	mux := &motmedelMux.Mux{}
	mux.SetContextKeyValuePairs = contextKeyValuePairs
	mux.Add(specifications...)

	PatchMux(mux)

	return mux
}
