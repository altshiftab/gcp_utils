package authorizer_request_parser_config

var (
	DefaultCookieName = "session"
)

type Config struct {
	SkipExp         bool
	CookieName      string
	AllowedRoles    []string
	AllowedTenantId string
	SuperAdminRoles []string
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

func WithSkipExp(skipExp bool) Option {
	return func(config *Config) {
		config.SkipExp = skipExp
	}
}

func WithCookieName(cookieName string) Option {
	return func(config *Config) {
		config.CookieName = cookieName
	}
}

func WithAllowedRoles(allowedRoles []string) Option {
	return func(config *Config) {
		config.AllowedRoles = allowedRoles
	}
}

func WithAllowedTenantId(allowedTenantId string) Option {
	return func(config *Config) {
		config.AllowedTenantId = allowedTenantId
	}
}

func WithSuperAdminRoles(superAdminRoles []string) Option {
	return func(config *Config) {
		config.SuperAdminRoles = superAdminRoles
	}
}
