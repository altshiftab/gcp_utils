package dbsc_refresh_endpoint_config

import "time"

var (
	DefaultPath              = "/api/session/dbsc/refresh"
	DefaultSessionDuration   = 30 * time.Minute
	DefaultChallengeDuration = 5 * time.Minute
)

type Config struct {
	Path              string
	SessionDuration   time.Duration
	ChallengeDuration time.Duration
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:              DefaultPath,
		SessionDuration:   DefaultSessionDuration,
		ChallengeDuration: DefaultChallengeDuration,
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

func WithChallengeDuration(challengeDuration time.Duration) Option {
	return func(config *Config) {
		config.ChallengeDuration = challengeDuration
	}
}
