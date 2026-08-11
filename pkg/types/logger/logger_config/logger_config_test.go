package logger_config

import (
	"bytes"
	"log/slog"
	"testing"

	gcpHttpContextExtractor "github.com/Motmedel/utils_go/pkg/cloud/gcp/types/http_context_extractor"
	"github.com/altshiftab/gcp_utils/pkg/http/types/http_context_extractor"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New(nil)
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.Writer != DefaultWriter {
		t.Errorf("writer: got %v", config.Writer)
	}
	if config.LogLevel != DefaultLogLevel {
		t.Errorf("log level: got %v", config.LogLevel)
	}
	if config.HttpContextExtractor != DefaultHttpContextExtractor {
		t.Errorf("http context extractor: got %v", config.HttpContextExtractor)
	}
	if config.GcpHttpContextExtractor != DefaultGcpLoggingExtractor {
		t.Errorf("gcp http context extractor: got %v", config.GcpHttpContextExtractor)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	httpContextExtractor := http_context_extractor.New()
	gcpLoggingExtractor := gcpHttpContextExtractor.New()

	testCases := []struct {
		name   string
		option Option
		check  func(t *testing.T, config *Config)
	}{
		{
			name:   "with writer",
			option: WithWriter(&buffer),
			check: func(t *testing.T, config *Config) {
				if config.Writer != &buffer {
					t.Errorf("writer: got %v", config.Writer)
				}
			},
		},
		{
			name:   "with log level",
			option: WithLogLevel(slog.LevelDebug),
			check: func(t *testing.T, config *Config) {
				if config.LogLevel != slog.LevelDebug {
					t.Errorf("log level: got %v", config.LogLevel)
				}
			},
		},
		{
			name:   "with http context extractor",
			option: WithHttpContextExtractor(httpContextExtractor),
			check: func(t *testing.T, config *Config) {
				if config.HttpContextExtractor != httpContextExtractor {
					t.Errorf("http context extractor: got %v", config.HttpContextExtractor)
				}
			},
		},
		{
			name:   "with gcp logging extractor",
			option: WithGcpLoggingExtractor(gcpLoggingExtractor),
			check: func(t *testing.T, config *Config) {
				if config.GcpHttpContextExtractor != gcpLoggingExtractor {
					t.Errorf("gcp http context extractor: got %v", config.GcpHttpContextExtractor)
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testCase.check(t, New(testCase.option))
		})
	}
}
