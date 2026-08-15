package service_config

import (
	"time"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
)

// DefaultShutdownTimeout leaves room within the time Cloud Run allows an
// instance between asking it to stop and killing it.
const DefaultShutdownTimeout = 9 * time.Second

type Config struct {
	Public                 bool
	StaticContentEndpoints []*endpoint.Endpoint
	Redirects              [][2]string
	ShutdownTimeout        time.Duration
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{ShutdownTimeout: DefaultShutdownTimeout}
	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithPublic(public bool) Option {
	return func(config *Config) {
		config.Public = public
	}
}

func WithStaticContentEndpoints(endpoints []*endpoint.Endpoint) Option {
	return func(config *Config) {
		config.StaticContentEndpoints = endpoints
	}
}

func WithRedirects(redirects [][2]string) Option {
	return func(config *Config) {
		config.Redirects = redirects
	}
}

// WithShutdownTimeout bounds how long the requests being handled are given to
// finish once the process has been asked to stop.
func WithShutdownTimeout(shutdownTimeout time.Duration) Option {
	return func(config *Config) {
		config.ShutdownTimeout = shutdownTimeout
	}
}
