package callback_endpoint_config

import (
	"context"
	"database/sql"

	"github.com/altshiftab/gcp_utils/pkg/http/login/database"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/oauth_flow"
)

var (
	DefaultCallbackCookieName = "callback_id"
	DefaultPopOauthFlow       = database.PopOauthFlow
)

type Config struct {
	CallbackCookieName string
	PopOauthFlow       func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error)
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CallbackCookieName: DefaultCallbackCookieName,
		PopOauthFlow:       DefaultPopOauthFlow,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithCallbackCookieName(callbackCookieName string) Option {
	return func(config *Config) {
		config.CallbackCookieName = callbackCookieName
	}
}

func WithPopOauthFlow(popOauthFlow func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error)) Option {
	return func(config *Config) {
		config.PopOauthFlow = popOauthFlow
	}
}
