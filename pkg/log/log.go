package log

import (
	"github.com/Motmedel/ecs_go/ecs"
	"github.com/Motmedel/gcp_logging_go/gcp_logging"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelJson "github.com/Motmedel/utils_go/pkg/json"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	altshiftGcpUtilsEnv "github.com/altshiftab/gcp_utils/pkg/env"
	"log/slog"
	"os"
	"runtime/debug"
	"snqk.dev/slog/meld"
)

func getHttpLogAttrs(httpContext *motmedelHttpTypes.HttpContext, logger *slog.Logger) []any {
	if httpContext == nil {
		return nil
	}

	if logger == nil {
		logger = slog.Default()
	}

	var logAttrs []any
	if httpContext != nil {
		ecsBase, err := ecs.ParseHttpContext(httpContext, ecs.DefaultMaskedHeaderExtractor)
		if err != nil {
			motmedelLog.LogError("An error occurred when parsing an HTTP context into ECS.", err, logger)
		}
		if ecsBase != nil {
			if baseMap, ok := motmedelJson.Jsonify(ecsBase).(map[string]any); ok {
				logAttrs = append(logAttrs, motmedelLog.AttrsFromMap(baseMap)...)
			} else {
				msg := "An ECS base object could not be converted into a jsonified map."
				motmedelLog.LogError(msg, &motmedelErrors.InputError{Message: msg, Input: ecsBase}, logger)
			}
		}

		gcpLogEntry, err := gcp_logging.ParseHttp(httpContext.Request, httpContext.Response)
		if err != nil {
			motmedelLog.LogError("An error occurred when parsing HTTP data into GCP LogEntry.", err, logger)
		}
		if gcpLogEntry != nil {
			if gcpLogEntryMap, ok := motmedelJson.Jsonify(ecsBase).(map[string]any); ok {
				logAttrs = append(logAttrs, motmedelLog.AttrsFromMap(gcpLogEntryMap)...)
			} else {
				msg := "A GCP LogEntry object could not be converted into a jsonified map."
				motmedelLog.LogError(msg, &motmedelErrors.InputError{Message: msg, Input: gcpLogEntry}, logger)
			}
		}
	}

	return logAttrs
}

func LogHttpError(message string, err error, logger *slog.Logger, httpContext *motmedelHttpTypes.HttpContext) {
	motmedelLog.LogError(message, err, logger.With(getHttpLogAttrs(httpContext, logger)...))
}

func LogHttpInfo(message string, logger *slog.Logger, httpContext *motmedelHttpTypes.HttpContext) {
	logger.Info(message, getHttpLogAttrs(httpContext, logger)...)
}

func LogHttpDebug(message string, logger *slog.Logger, httpContext *motmedelHttpTypes.HttpContext) {
	logger.Debug(message, getHttpLogAttrs(httpContext, logger)...)
}

func MakeLogger(logger *slog.Logger, exit bool) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(altshiftGcpUtilsEnv.GetLogLevelWithDefault())); err != nil {
		if logger != nil {
			motmedelLog.LogError("An error occurred when parsing the log level.", err, logger)
		}
		if exit {
			os.Exit(1)
		}

		return nil, err
	}

	outLogger := slog.New(
		meld.NewHandler(
			slog.NewJSONHandler(
				os.Stdout,
				&slog.HandlerOptions{
					AddSource:   true,
					Level:       level,
					ReplaceAttr: gcp_logging.ReplaceAttr,
				},
			),
		),
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
			outLogger = outLogger.With(slog.Group("labels", labelAttrs...))
		}
	}

	return outLogger, nil
}
