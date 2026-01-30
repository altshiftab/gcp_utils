package dbsc_register_endpoint_config

import (
	"context"
	"database/sql"

	"github.com/altshiftab/gcp_utils/pkg/http/login/database"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
)

var (
	DefaultPath                                  = "/api/session/dbsc/register"
	DefaultRefreshPath                           = dbsc_refresh_endpoint_config.DefaultPath
	DefaultUpdateAuthenticationWithDbscPublicKey = database.UpdateAuthenticationWithDbscPublicKey
)

type Config struct {
	Path                                  string
	RefreshPath                           string
	UpdateAuthenticationWithDbscPublicKey func(ctx context.Context, id string, key []byte, database *sql.DB) error
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:                                  DefaultPath,
		RefreshPath:                           DefaultRefreshPath,
		UpdateAuthenticationWithDbscPublicKey: DefaultUpdateAuthenticationWithDbscPublicKey,
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

func WithUpdateAuthenticationWithDbscPublicKey(updateAuthenticationWithDbscPublicKey func(ctx context.Context, id string, key []byte, database *sql.DB) error) Option {
	return func(config *Config) {
		config.UpdateAuthenticationWithDbscPublicKey = updateAuthenticationWithDbscPublicKey
	}
}
