package logger

import (
	"log/slog"
	"runtime/debug"

	gcpLogger "github.com/Motmedel/utils_go/pkg/cloud/gcp/types/logger"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelContextLogger "github.com/Motmedel/utils_go/pkg/log/context_logger"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/altshiftab/gcp_utils/pkg/types/logger/entry_size_guard"
	"github.com/altshiftab/gcp_utils/pkg/types/logger/logger_config"
)

func New(options ...logger_config.Option) *motmedelErrorLogger.Logger {
	config := logger_config.New(options...)

	slogger := motmedelContextLogger.New(
		slog.NewJSONHandler(
			// Oversized entries are rejected by Cloud Logging wholesale; the
			// guard reduces them instead.
			entry_size_guard.New(config.Writer),
			&slog.HandlerOptions{Level: config.LogLevel, ReplaceAttr: gcpLogger.ReplaceAttr},
		),
		&motmedelLog.ErrorContextExtractor{
			ContextExtractors: []motmedelLog.ContextExtractor{
				config.HttpContextExtractor,
			},
		},
		config.HttpContextExtractor,
		config.GcpHttpContextExtractor,
	)

	if buildInfo, ok := debug.ReadBuildInfo(); ok && buildInfo != nil {
		var labelAttrs []any
		for _, buildSetting := range buildInfo.Settings {
			key := buildSetting.Key
			if key == "vcs.revision" || key == "vcs.time" {
				labelAttrs = append(labelAttrs, slog.String(key, buildSetting.Value))
			}
		}

		if len(labelAttrs) > 0 {
			slogger = slogger.With(slog.Group("labels", labelAttrs...))
		}
	}

	return &motmedelErrorLogger.Logger{Logger: slogger}
}
