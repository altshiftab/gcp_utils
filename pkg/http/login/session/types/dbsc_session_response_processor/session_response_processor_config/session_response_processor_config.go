package session_response_processor_config

import "github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager/session_manager_config"

var (
	DefaultAlgs = session_manager_config.DefaultDbscAlgs
)

type Config struct {
	Algs []string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Algs: DefaultAlgs,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithAlgs(allowedAlgs []string) Option {
	return func(config *Config) {
		config.Algs = allowedAlgs
	}
}
