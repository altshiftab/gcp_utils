package logger_config

import (
	"io"
	"log/slog"
	"os"

	gcpHttpContextExtractor "github.com/Motmedel/utils_go/pkg/cloud/gcp/types/http_context_extractor"
	"github.com/altshiftab/gcp_utils/pkg/http/types/http_context_extractor"
)

const (
	DefaultLogLevel = slog.LevelInfo
)

var (
	DefaultWriter               = os.Stdout
	DefaultHttpContextExtractor = http_context_extractor.New()
	DefaultGcpLoggingExtractor  = gcpHttpContextExtractor.New()
)

type Config struct {
	Writer                  io.Writer
	LogLevel                slog.Level
	HttpContextExtractor    *http_context_extractor.Extractor
	GcpHttpContextExtractor *gcpHttpContextExtractor.Extractor
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Writer:                  DefaultWriter,
		LogLevel:                DefaultLogLevel,
		HttpContextExtractor:    DefaultHttpContextExtractor,
		GcpHttpContextExtractor: DefaultGcpLoggingExtractor,
	}
	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithWriter(writer io.Writer) Option {
	return func(config *Config) {
		config.Writer = writer
	}
}

func WithLogLevel(logLevel slog.Level) Option {
	return func(config *Config) {
		config.LogLevel = logLevel
	}
}

func WithHttpContextExtractor(httpContextExtractor *http_context_extractor.Extractor) Option {
	return func(config *Config) {
		config.HttpContextExtractor = httpContextExtractor
	}
}

func WithGcpLoggingExtractor(gcpLoggingExtractor *gcpHttpContextExtractor.Extractor) Option {
	return func(config *Config) {
		config.GcpHttpContextExtractor = gcpLoggingExtractor
	}
}
