package path_config

type Option func(*Config)

const (
    DefaultLoginPath     = "/api/login/microsoft"
    DefaultCallbackPath  = "/api/callback/microsoft"
    DefaultTokenPath     = "/api/token/microsoft"
)

type Config struct {
    LoginPath      string
    CallbackPath   string
    TokenPath      string
}

func New(options ...Option) *Config {
    config := &Config{
        LoginPath:      DefaultLoginPath,
        CallbackPath:   DefaultCallbackPath,
        TokenPath:      DefaultTokenPath,
    }

    for _, option := range options {
        if option != nil {
            option(config)
        }
    }

    return config
}

func WithLoginPath(loginPath string) Option {
    return func(config *Config) { config.LoginPath = loginPath }
}

func WithCallbackPath(callbackPath string) Option {
    return func(config *Config) { config.CallbackPath = callbackPath }
}

func WithTokenPath(tokenPath string) Option {
    return func(config *Config) { config.TokenPath = tokenPath }
}
