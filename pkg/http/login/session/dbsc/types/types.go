package types

import (
	"net/url"
	"time"
)

type Configuration struct {
	OriginUrl         *url.URL
	RegisterPath      string
	RefreshPath       string
	AllowedAlgs       []string
	ChallengeDuration time.Duration
}
