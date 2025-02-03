package env

import (
	"errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"log/slog"
	"os"
	"strings"
)

const (
	LogLevelVariableName         = "LOG_LEVEL"
	ProjectIdVariableName        = "PROJECT_ID"
	ListenAddressVariableName    = "LISTEN_ADDRESS"
	DnsServerAddressVariableName = "DNS_SERVER_ADDRESS"
	TopicIdVariableName          = "TOPIC_ID"
)

const (
	DefaultLogLevel         = "INFO"
	DefaultProjectId        = "*detect-project-id*"
	DefaultListenAddress    = "0.0.0.0:8080"
	DefaultDnsServerAddress = "169.254.169.254:53"
)

const noDataInEnvironmentVariablePrefix = "No data in environment variable"

func ReadEnvironmentVariable(name string, logger *slog.Logger, exit bool) string {
	value := os.Getenv(name)
	if value == "" {
		if logger != nil {
			motmedelLog.LogError(
				noDataInEnvironmentVariablePrefix+": "+name,
				errors.New(strings.ToLower(noDataInEnvironmentVariablePrefix)),
				logger,
			)
		}
		if exit {
			os.Exit(1)
		}
	}
	return value
}

func GetTopicId(logger *slog.Logger, exit bool) string {
	return ReadEnvironmentVariable(TopicIdVariableName, logger, exit)
}

func GetListenAddress(logger *slog.Logger, exit bool) string {
	return ReadEnvironmentVariable(ListenAddressVariableName, logger, exit)
}

func GetListenAddressWithDefault() string {
	if listenAddress := GetListenAddress(nil, false); listenAddress == "" {
		return DefaultListenAddress
	} else {
		return listenAddress
	}
}

func GetProjectId(logger *slog.Logger, exit bool) string {
	return ReadEnvironmentVariable(ProjectIdVariableName, logger, exit)
}

func GetProjectIdWithDefault() string {
	if projectId := GetProjectId(nil, false); projectId == "" {
		return DefaultProjectId
	} else {
		return projectId
	}
}

func GetDnsServerAddress(logger *slog.Logger, exit bool) string {
	return ReadEnvironmentVariable(DnsServerAddressVariableName, logger, exit)
}

func GetDnsServerAddressWithDefault() string {
	if dnsServerAddress := GetDnsServerAddress(nil, false); dnsServerAddress == "" {
		return DefaultDnsServerAddress
	} else {
		return dnsServerAddress
	}
}

func GetLogLevel(logger *slog.Logger, exit bool) string {
	return ReadEnvironmentVariable(LogLevelVariableName, logger, exit)
}

func GetLogLevelWithDefault() string {
	if logLevel := GetLogLevel(nil, false); logLevel == "" {
		return DefaultLogLevel
	} else {
		return logLevel
	}
}
