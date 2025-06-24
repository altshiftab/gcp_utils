package log

import (
	"context"
	"fmt"
	dnsUtilsLog "github.com/Motmedel/dns_utils/pkg/log"
	gcpLogging "github.com/Motmedel/gcp_logging_go/pkg/log"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpLog "github.com/Motmedel/utils_go/pkg/http/log"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelContextLogger "github.com/Motmedel/utils_go/pkg/log/context_logger"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	altshiftGcpUtilsEnv "github.com/altshiftab/gcp_utils/pkg/env"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
)

func New(writer io.Writer, level slog.Level) *motmedelErrorLogger.Logger {
	slogger := motmedelContextLogger.New(
		slog.NewJSONHandler(
			writer,
			&slog.HandlerOptions{Level: level, ReplaceAttr: gcpLogging.LoggerReplaceAttr},
		),
		&motmedelLog.ErrorContextExtractor{
			ContextExtractors: []motmedelLog.ContextExtractor{
				&motmedelHttpLog.HttpContextExtractor{},
				&dnsUtilsLog.DnsContextExtractor,
			},
		},
		&motmedelHttpLog.HttpContextExtractor{},
		&gcpLogging.HttpContextExtractor{},
		&dnsUtilsLog.DnsContextExtractor,
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

func Default() (*motmedelErrorLogger.Logger, error) {
	var level slog.Level
	levelTextData := []byte(altshiftGcpUtilsEnv.GetLogLevelWithDefault())
	if err := level.UnmarshalText(levelTextData); err != nil {
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("slog level unmarshal text: %w", err),
			levelTextData,
		)
	}

	return New(os.Stdout, level), nil
}

func DefaultFatal(ctx context.Context) *motmedelErrorLogger.Logger {
	logger, err := Default()
	if err != nil {
		slog.New(slog.NewJSONHandler(os.Stdout, nil)).ErrorContext(
			motmedelContext.WithErrorContextValue(ctx, fmt.Errorf("default: %w", err)),
			"An error occurred when making a default logger.",
		)
		os.Exit(1)
	}

	return logger
}
