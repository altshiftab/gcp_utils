package credentials_config


type Option func(*Config)

const (
	DefaultCredentialsPath  = "credentials.json"
)

type Config struct {
	CredentialsPath  string
}

func New(options ...Option) *Config {
	config := &Config{
		CredentialsPath:      DefaultCredentialsPath,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithCredentialsPath(tokenPath string) Option {
	return func(config *Config) {
		config.CredentialsPath = tokenPath
	}
}
