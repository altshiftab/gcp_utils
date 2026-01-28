package dbsc_register_endpoint_config

import (
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
)

var (
	DefaultPath        = "/api/session/dbsc/register"
	DefaultRefreshPath = dbsc_refresh_endpoint_config.DefaultPath
)

type Config struct {
	Path        string
	RefreshPath string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:        DefaultPath,
		RefreshPath: DefaultRefreshPath,
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

func WithRefreshPath(refreshPath string) Option {
	return func(config *Config) {
		config.RefreshPath = refreshPath
	}
}
