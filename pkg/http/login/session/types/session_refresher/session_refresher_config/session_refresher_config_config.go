package session_refresher_config

var (
	DefaultCookieName = "session"
)

type Config struct {
	CookieName string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CookieName: DefaultCookieName,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithCookieName(cookieName string) Option {
	return func(config *Config) {
		config.CookieName = cookieName
	}
}
