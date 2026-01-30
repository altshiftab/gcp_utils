package dbsc_session_response_processor_config

import (
	"context"
	"database/sql"

	"github.com/altshiftab/gcp_utils/pkg/http/login/database"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/dbsc_challenge"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager/session_manager_config"
)

var (
	DefaultAlgs             = session_manager_config.DefaultDbscAlgs
	DefaultPopDbscChallenge = database.PopDbscChallenge
)

type Config struct {
	Algs             []string
	PopDbscChallenge func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error)
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Algs:             DefaultAlgs,
		PopDbscChallenge: DefaultPopDbscChallenge,
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

func WithPopDbscChallenge(popDbscChallenge func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error)) Option {
	return func(config *Config) {
		config.PopDbscChallenge = popDbscChallenge
	}
}
