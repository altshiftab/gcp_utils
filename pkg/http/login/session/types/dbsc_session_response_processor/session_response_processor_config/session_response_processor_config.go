package session_response_processor_config

var (
	DefaultAlgs = []string{"ES256"}
)

type Config struct {
	Algs []string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Algs: DefaultAlgs,
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
