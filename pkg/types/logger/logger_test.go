package logger

import (
	"bytes"
	"encoding/json/v2"
	"log/slog"
	"testing"

	"github.com/altshiftab/gcp_utils/pkg/types/logger/logger_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	errorLogger := New(logger_config.WithWriter(&buffer))
	if errorLogger == nil || errorLogger.Logger == nil {
		t.Fatalf("nil logger")
	}

	errorLogger.Info("test message")

	var record map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
		t.Fatalf("json unmarshal log record: %v (%q)", err, buffer.String())
	}

	if record["message"] != "test message" {
		t.Errorf("message: got %v in %v", record["message"], record)
	}
	if record["severity"] != "INFO" {
		t.Errorf("severity: got %v in %v", record["severity"], record)
	}
}

func TestNewLogLevelFilters(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	errorLogger := New(
		logger_config.WithWriter(&buffer),
		logger_config.WithLogLevel(slog.LevelWarn),
	)

	errorLogger.Info("filtered")
	if buffer.Len() != 0 {
		t.Errorf("expected the info record to be filtered, got %q", buffer.String())
	}

	errorLogger.Warn("emitted")
	if buffer.Len() == 0 {
		t.Errorf("expected the warn record to be emitted")
	}
}
