package path_config

type Option func(*Config)

const (
	DefaultLoginPath = "/api/login/google"
	DefaultCallbackPath = "/api/callback/google"
	DefaultFedcmLoginPath = "/api/login/fedcm/google"
)

type Config struct {
	LoginPath string
	CallbackPath string
	FedcmLoginPath string
}

func New(options ...Option) *Config {
	config := &Config{
		LoginPath: DefaultLoginPath,
		CallbackPath: DefaultCallbackPath,
		FedcmLoginPath: DefaultFedcmLoginPath,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithLoginPath(loginPath string) Option {
	return func(config *Config) {
		config.LoginPath = loginPath
	}
}

func WithCallbackPath(callbackPath string) Option {
	return func(config *Config) {
		config.CallbackPath = callbackPath
	}
}

func WithFedcmLoginPath(fedcmLoginPath string) Option {
	return func(config *Config) {
		config.FedcmLoginPath = fedcmLoginPath
	}
}