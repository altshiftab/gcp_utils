package cse_config

import (
	"github.com/go-jose/go-jose/v4"
)

const (
	DefaultClientPublicJwkHeader = "X-Client-Public-Jwk"
	DefaultContentEncryption     = "A256GCM"
	DefaultKeyAlgorithm          = "ECDH-ES"
	DefaultKeyAlgorithmCurve     = "P-256"
)

var DefaultEncrypterOptions = (&jose.EncrypterOptions{}).WithContentType("application/json")

type Option func(configuration *Config)

type Config struct {
	PrivateKey            any
	KeyIdentifier         string
	ClientPublicJwkHeader string
	KeyAlgorithm          jose.KeyAlgorithm
	ContentEncryption     jose.ContentEncryption
	EncrypterOptions      *jose.EncrypterOptions
}

func New(privateKey any, keyIdentifier string, options ...Option) *Config {
	config := &Config{
		PrivateKey:            privateKey,
		KeyIdentifier:         keyIdentifier,
		ClientPublicJwkHeader: DefaultClientPublicJwkHeader,
		KeyAlgorithm:          DefaultKeyAlgorithm,
		ContentEncryption:     DefaultContentEncryption,
		EncrypterOptions:      DefaultEncrypterOptions,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithClientPublicJwkHeader(clientPublicJwkHeader string) Option {
	return func(config *Config) {
		config.ClientPublicJwkHeader = clientPublicJwkHeader
	}
}

func WithContentEncryption(contentEncryption jose.ContentEncryption) Option {
	return func(config *Config) {
		config.ContentEncryption = contentEncryption
	}
}

func WithKeyAlgorithm(keyAlgorithm jose.KeyAlgorithm) Option {
	return func(config *Config) {
		config.KeyAlgorithm = keyAlgorithm
	}
}

func WithEncrypterOptions(encrypterOptions *jose.EncrypterOptions) Option {
	return func(config *Config) {
		config.EncrypterOptions = encrypterOptions
	}
}
