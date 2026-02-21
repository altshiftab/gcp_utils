package service_config

import "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"

type Config struct {
	Public                 bool
	StaticContentEndpoints []*endpoint.Endpoint
	Redirects              [][2]string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{}
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
