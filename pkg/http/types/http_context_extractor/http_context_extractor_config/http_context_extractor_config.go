package http_context_extractor_config

import "github.com/Motmedel/utils_go/pkg/schema"

type MaskedHeader struct {
	Url     *schema.Url
	Headers []string
}

type Config struct {
	ReplaceableMessages    []string
	MaskedUrlParams        []*schema.Url
	MaskedHeaders          []*MaskedHeader
	MaskedRequestBodyUrls  []*schema.Url
	MaskedResponseBodyUrls []*schema.Url
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

func WithReplaceableMessages(replaceableMessages ...string) Option {
	return func(config *Config) {
		config.ReplaceableMessages = replaceableMessages
	}
}

func WithMaskedUrlParams(urlPatterns ...*schema.Url) Option {
	return func(config *Config) {
		config.MaskedUrlParams = urlPatterns
	}
}

func WithMaskedHeaders(maskedHeaders ...*MaskedHeader) Option {
	return func(config *Config) {
		config.MaskedHeaders = maskedHeaders
	}
}

func WithMaskedRequestBodyUrls(urlPatterns ...*schema.Url) Option {
	return func(config *Config) {
		config.MaskedRequestBodyUrls = urlPatterns
	}
}

func WithMaskedResponseBodyUrls(urlPatterns ...*schema.Url) Option {
	return func(config *Config) {
		config.MaskedResponseBodyUrls = urlPatterns
	}
}
