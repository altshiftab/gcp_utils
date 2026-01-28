package env

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
)

const (
	LogLevelVariableName         = "LOG_LEVEL"
	ProjectIdVariableName        = "PROJECT_ID"
	PortVariableName             = "PORT"
	DnsServerAddressVariableName = "DNS_SERVER_ADDRESS"
	TopicIdVariableName          = "TOPIC_ID"
)

const (
	DefaultLogLevel         = "INFO"
	DefaultProjectId        = "*detect-project-id*"
	DefaultDnsServerAddress = "169.254.169.254:53"
	DefaultPort             = "8080"
)

var (
	ErrNotPresent = errors.New("non-present environment variable")
	ErrEmpty      = errors.New("empty environment variable")
)

func ReadEnvironmentVariableFatal(ctx context.Context, name string) string {
	value, found := os.LookupEnv(name)

	var err error
	if !found {
		err = motmedelErrors.NewWithTrace(fmt.Errorf("%w: %q", ErrNotPresent, name), name)
	} else if value == "" {
		err = motmedelErrors.NewWithTrace(fmt.Errorf("%w: %q", ErrEmpty, name), name)
	}

	if err != nil {
		slog.ErrorContext(
			motmedelContext.WithError(ctx, err),
			"An environment variable could not be read.",
		)
		os.Exit(1)
	}

	return value
}

func GetTopicIdFatal(ctx context.Context) string {
	return ReadEnvironmentVariableFatal(ctx, TopicIdVariableName)
}

func GetPortWithDefault() string {
	if port := os.Getenv(PortVariableName); port != "" {
		return port
	} else {
		return DefaultPort
	}
}

func GetProjectIdFatal(ctx context.Context) string {
	return ReadEnvironmentVariableFatal(ctx, ProjectIdVariableName)
}

func GetProjectIdWithDefault() string {
	if projectId := os.Getenv(ProjectIdVariableName); projectId == "" {
		return DefaultProjectId
	} else {
		return projectId
	}
}

func GetDnsServerAddressFatal(ctx context.Context) string {
	return ReadEnvironmentVariableFatal(ctx, DnsServerAddressVariableName)
}

func GetDnsServerAddressWithDefault() string {
	if dnsServerAddress := os.Getenv(DnsServerAddressVariableName); dnsServerAddress == "" {
		return DefaultDnsServerAddress
	} else {
		return dnsServerAddress
	}
}

func GetLogLevelFatal(ctx context.Context) string {
	return ReadEnvironmentVariableFatal(ctx, LogLevelVariableName)
}

func GetLogLevelWithDefault() string {
	if logLevel := os.Getenv(LogLevelVariableName); logLevel == "" {
		return DefaultLogLevel
	} else {
		return logLevel
	}
}
