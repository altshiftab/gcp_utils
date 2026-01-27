package login_endpoint_config

import (
	"time"

	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
)

var (
	DefaultCallbackCookieName     = callback_endpoint_config.DefaultCallbackCookieName
	DefaultCallbackCookieDuration = 8 * time.Minute
)

type Config struct {
	CallbackCookieDuration time.Duration
	CallbackCookieName     string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CallbackCookieDuration: DefaultCallbackCookieDuration,
		CallbackCookieName:     DefaultCallbackCookieName,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithCallbackCookieDuration(callbackCookieDuration time.Duration) Option {
	return func(config *Config) {
		config.CallbackCookieDuration = callbackCookieDuration
	}
}

func WithCallbackCookieName(callbackCookieName string) Option {
	return func(config *Config) {
		config.CallbackCookieName = callbackCookieName
	}
}
