package template_options

type AuthenticationMode string
const (
	AuthenticationModeCookie AuthenticationMode = "cookie"
	AuthenticationModeBearer AuthenticationMode = "bearer"
)

const (
	DefaultCseClientPublicJwkHeader = "X-Client-Public-Jwk"
	DefaultCseContentEncryption     = "A256GCM"
	DefaultCseKeyAlgorithm          = "ECDH-ES"
	DefaultCseKeyAlgorithmCurve     = "P-256"
)

type Option func(*Options)

type Options struct {
	AuthenticationMode AuthenticationMode
	CseClientPublicJwkHeader string
	CseContentEncryption     string
	CseKeyAlgorithm          string
	CseKeyAlgorithmCurve     string
}

func New(options ...Option) *Options {
	opts := &Options{
		AuthenticationMode: AuthenticationModeCookie,
		CseClientPublicJwkHeader: DefaultCseClientPublicJwkHeader,
		CseContentEncryption:     DefaultCseContentEncryption,
		CseKeyAlgorithm:          DefaultCseKeyAlgorithm,
		CseKeyAlgorithmCurve:     DefaultCseKeyAlgorithmCurve,
	}
	for _, option := range options {
		if option != nil {
			option(opts)
		}
	}
	return opts
}

func WithAuthenticationMode(authenticationMode AuthenticationMode) Option {
	return func(opts *Options) {
		opts.AuthenticationMode = authenticationMode
	}
}

func WithCseClientPublicJwkHeader(header string) Option {
	return func(opts *Options) {
		opts.CseClientPublicJwkHeader = header
	}
}

func WithCseContentEncryption(contentEncryption string) Option {
	return func(opts *Options) {
		opts.CseContentEncryption = contentEncryption
	}
}

func WithCseKeyAlgorithm(keyAlgorithm string) Option {
	return func(opts *Options) {
		opts.CseKeyAlgorithm = keyAlgorithm
	}
}

func WithCseKeyAlgorithmCurve(keyAlgorithmCurve string) Option {
	return func(opts *Options) {
		opts.CseKeyAlgorithmCurve = keyAlgorithmCurve
	}
}
