package config

import (
	"log/slog"

	gcpLogging "github.com/Motmedel/gcp_logging_go/pkg/log"
	motmedelHttpLog "github.com/Motmedel/utils_go/pkg/http/log"
)

const (
	DefaultLogLevel = slog.LevelInfo
)

var (
	DefaultHttpContextExtractor = &motmedelHttpLog.HttpContextExtractor{}
	DefaultGcpLoggingExtractor  = &gcpLogging.HttpContextExtractor{}
)

type Option func(configuration *Config)

type Config struct {
	LogLevel slog.Level
	HttpContextExtractor *motmedelHttpLog.HttpContextExtractor
	GcpLoggingExtractor *gcpLogging.HttpContextExtractor
}

func New(options ...Option) *Config {
	config := &Config{
		LogLevel:             DefaultLogLevel,
		HttpContextExtractor: DefaultHttpContextExtractor,
		GcpLoggingExtractor:  DefaultGcpLoggingExtractor,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithLogLevel(logLevel slog.Level) Option {
	return func(config *Config) {
		config.LogLevel = logLevel
	}
}

func WithHttpContextExtractor(httpContextExtractor *motmedelHttpLog.HttpContextExtractor) Option {
	return func(config *Config) {
		config.HttpContextExtractor = httpContextExtractor
	}
}

func WithGcpLoggingExtractor(gcpLoggingExtractor *gcpLogging.HttpContextExtractor) Option {
	return func(config *Config) {
		config.GcpLoggingExtractor = gcpLoggingExtractor
	}
}
