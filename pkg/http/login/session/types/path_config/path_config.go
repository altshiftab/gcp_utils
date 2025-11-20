package path_config

type Option func(*Config)

const (
	DefaultRefreshPath = "/api/session/refresh"
	DefaultEndPath     = "/api/session/end"
)

type Config struct {
	RefreshPath string
	EndPath string
}

func New(options ...Option) *Config {
	config := &Config{
		RefreshPath: DefaultRefreshPath,
		EndPath: DefaultEndPath,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithRefreshPath(refreshPath string) Option {
	return func(config *Config) {
		config.RefreshPath = refreshPath
	}
}

func WithEndPath(endPath string) Option {
	return func(config *Config) {
		config.EndPath = endPath
	}
}