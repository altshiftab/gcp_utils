package session_manager_config

import (
	"time"

	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
)

var (
	DefaultCookieName = "session"
	// TODO: This could change as DBSC becomes more mature?
	DefaultInitialSessionDuration = 12 * time.Hour
	DefaultAuthenticationDuration = 24 * 7 * time.Hour
	DefaultDbscChallengeDuration  = dbsc_refresh_endpoint_config.DefaultChallengeDuration
	DefaultDbscRegisterPath       = dbsc_register_endpoint_config.DefaultPath
	DefaultDbscAlgs               = []string{"ES256"}
)

type Config struct {
	CookieName             string
	InitialSessionDuration time.Duration
	AuthenticationDuration time.Duration
	DbscChallengeDuration  time.Duration
	DbscRegisterPath       string
	DbscAlgs               []string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CookieName:             DefaultCookieName,
		InitialSessionDuration: DefaultInitialSessionDuration,
		AuthenticationDuration: DefaultAuthenticationDuration,
		DbscChallengeDuration:  DefaultDbscChallengeDuration,
		DbscRegisterPath:       DefaultDbscRegisterPath,
		DbscAlgs:               DefaultDbscAlgs,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithCookieName(cookieName string) Option {
	return func(config *Config) {
		config.CookieName = cookieName
	}
}

func WithInitialSessionDuration(initialSessionDuration time.Duration) Option {
	return func(config *Config) {
		config.InitialSessionDuration = initialSessionDuration
	}
}

func WithAuthenticationDuration(authenticationDuration time.Duration) Option {
	return func(config *Config) {
		config.AuthenticationDuration = authenticationDuration
	}
}

func WithDbscChallengeDuration(dbscChallengeDuration time.Duration) Option {
	return func(config *Config) {
		config.DbscChallengeDuration = dbscChallengeDuration
	}
}

func WithDbscRegisterPath(dbscRegisterPath string) Option {
	return func(config *Config) {
		config.DbscRegisterPath = dbscRegisterPath
	}
}

func WithDbscAlgs(dbscAlgs []string) Option {
	return func(config *Config) {
		config.DbscAlgs = dbscAlgs
	}
}
