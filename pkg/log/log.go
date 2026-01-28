package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"

	gcpLogging "github.com/Motmedel/gcp_logging_go/pkg/log"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelContextLogger "github.com/Motmedel/utils_go/pkg/log/context_logger"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	altshiftGcpUtilsEnv "github.com/altshiftab/gcp_utils/pkg/env"
	configPkg "github.com/altshiftab/gcp_utils/pkg/log/types/config"
)

func New(writer io.Writer, options ...configPkg.Option) *motmedelErrorLogger.Logger {
	config := configPkg.New(options...)

	slogger := motmedelContextLogger.New(
		slog.NewJSONHandler(
			writer,
			&slog.HandlerOptions{Level: config.LogLevel, ReplaceAttr: gcpLogging.LoggerReplaceAttr},
		),
		&motmedelLog.ErrorContextExtractor{
			ContextExtractors: []motmedelLog.ContextExtractor{
				config.HttpContextExtractor,
			},
		},
		config.HttpContextExtractor,
		config.GcpLoggingExtractor,
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

func Default(options ...configPkg.Option) (*motmedelErrorLogger.Logger, error) {
	var level slog.Level
	levelTextData := []byte(altshiftGcpUtilsEnv.GetLogLevelWithDefault())
	if err := level.UnmarshalText(levelTextData); err != nil {
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("slog level unmarshal text: %w", err),
			levelTextData,
		)
	}

	options = append(options, configPkg.WithLogLevel(level))

	return New(os.Stdout, options...), nil
}

func DefaultFatal(ctx context.Context, options ...configPkg.Option) *motmedelErrorLogger.Logger {
	logger, err := Default(options...)
	if err != nil {
		slog.New(slog.NewJSONHandler(os.Stdout, nil)).ErrorContext(
			motmedelContext.WithError(ctx, fmt.Errorf("default: %w", err)),
			"An error occurred when making a default logger.",
		)
		os.Exit(1)
	}

	return logger
}
