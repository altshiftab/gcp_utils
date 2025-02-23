package log

import (
	"fmt"
	"github.com/Motmedel/gcp_logging_go/gcp_logging"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpLog "github.com/Motmedel/utils_go/pkg/http/log"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	altshiftGcpUtilsEnv "github.com/altshiftab/gcp_utils/pkg/env"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"snqk.dev/slog/meld"
)

func MakeLoggerWithWriter(writer io.Writer) (*motmedelLog.Logger, error) {
	var level slog.Level
	levelTextData := []byte(altshiftGcpUtilsEnv.GetLogLevelWithDefault())
	if err := level.UnmarshalText(levelTextData); err != nil {
		return nil, motmedelErrors.MakeError(
			fmt.Errorf("slog level unmarshal text: %w", err),
			levelTextData,
		)
	}

	// TODO: I'm not sure about the order; must be specific for meld to work?
	outLogger := slog.New(
		meld.NewHandler(
			&motmedelLog.ContextHandler{
				Handler: slog.NewJSONHandler(
					writer,
					&slog.HandlerOptions{
						AddSource:   true,
						Level:       level,
						ReplaceAttr: gcp_logging.ReplaceAttr,
					},
				),
				Extractors: []motmedelLog.ContextExtractor{
					motmedelLog.ErrorContextExtractor,
					&motmedelHttpLog.HttpContextExtractor{},
					gcp_logging.HttpContextExtractor,
				},
			},
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

	return &motmedelLog.Logger{Logger: outLogger}, nil

}

func MakeLogger() (*motmedelLog.Logger, error) {
	return MakeLoggerWithWriter(os.Stdout)
}
