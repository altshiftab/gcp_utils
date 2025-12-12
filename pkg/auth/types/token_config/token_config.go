package token_config

type Option func(*Config)

const (
	DefaultTokenPath  = "token.json"
	DefaultWriteToken = true
)

type Config struct {
	TokenPath  string
	WriteToken bool
}

func New(options ...Option) *Config {
	config := &Config{
		TokenPath:      DefaultTokenPath,
		WriteToken:     DefaultWriteToken,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithTokenPath(tokenPath string) Option {
	return func(config *Config) {
		config.TokenPath = tokenPath
	}
}

func WithWriteToken(writeToken bool) Option {
	return func(config *Config) {
		config.WriteToken = writeToken
	}
}
