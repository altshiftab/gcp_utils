package refresh_endpoint_config

import "time"

var (
	DefaultPath            = "/api/session/refresh"
	DefaultSessionDuration = 12 * time.Hour
)

type Config struct {
	Path            string
	SessionDuration time.Duration
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:            DefaultPath,
		SessionDuration: DefaultSessionDuration,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithPath(path string) Option {
	return func(config *Config) {
		config.Path = path
	}
}

func WithSessionDuration(sessionDuration time.Duration) Option {
	return func(config *Config) {
		config.SessionDuration = sessionDuration
	}
}
