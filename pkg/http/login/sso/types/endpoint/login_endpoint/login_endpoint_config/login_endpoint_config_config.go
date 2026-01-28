package login_endpoint_config

import (
	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
)

var (
	DefaultCallbackCookieName = callback_endpoint_config.DefaultCallbackCookieName
)

type Config struct {
	CallbackCookieName string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CallbackCookieName: DefaultCallbackCookieName,
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
