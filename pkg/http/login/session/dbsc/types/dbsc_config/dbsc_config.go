package dbsc_config

import (
	"errors"
	"net/url"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelNetErrors "github.com/Motmedel/utils_go/pkg/net/errors"
)

var (
	ErrNilConfig = errors.New("nil config")
)

type Option func(*Config)

var (
	DefaultAllowedAlgs = []string{"ES256"}
)

const (
	DefaultRegisterPath      = "/api/session/dbsc/register"
	DefaultRefreshPath       = "/api/session/dbsc/refresh"
	DefaultChallengeDuration = 1 * time.Minute
)

type Config struct {
	OriginUrl         *url.URL
	RegisterPath      string
	RefreshPath       string
	AllowedAlgs       []string
	ChallengeDuration time.Duration
}

func New(originUrl *url.URL, options ...Option) (*Config, error) {
	if originUrl == nil {
		return nil, motmedelErrors.NewWithTrace(motmedelNetErrors.ErrNilUrl)
	}

	config := &Config{
		OriginUrl:         originUrl,
		RefreshPath:       DefaultRefreshPath,
		RegisterPath:      DefaultRegisterPath,
		AllowedAlgs:       DefaultAllowedAlgs,
		ChallengeDuration: DefaultChallengeDuration,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config, nil
}
