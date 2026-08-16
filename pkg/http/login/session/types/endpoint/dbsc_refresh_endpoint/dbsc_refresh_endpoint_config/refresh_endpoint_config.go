package dbsc_refresh_endpoint_config

import (
	"context"
	"database/sql"
	"time"

	"github.com/altshiftab/gcp_utils/pkg/http/login/database"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/authentication"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session"
)

var (
	DefaultPath = "/api/session/dbsc/refresh"
	// The same fifteen minutes as an ordinary session: revocation is only enforced when a session
	// is refreshed, so this is how long a revoked session stays usable, and binding it to a device
	// does not change that.
	//
	// The browser refreshes a device bound session proactively once its cookie has two minutes or
	// less remaining (Chromium's kProactiveRefreshThreshold). A duration at or below that makes it
	// refresh on essentially every request, so keep this comfortably above two minutes.
	DefaultSessionDuration             = 15 * time.Minute
	DefaultChallengeDuration           = 5 * time.Minute
	DefaultInsertDbscChallenge         = database.InsertDbscChallenge
	DefaultSelectRefreshAuthentication = database.SelectRefreshAuthentication
	DefaultGenerateDbscChallenge       = session.GenerateDbscChallenge
)

type Config struct {
	Path                        string
	SessionDuration             time.Duration
	ChallengeDuration           time.Duration
	InsertDbscChallenge         func(ctx context.Context, challenge string, authenticationId string, challengeDuration time.Duration, db *sql.DB) error
	SelectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)
	GenerateDbscChallenge       func() (string, error)
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:                        DefaultPath,
		SessionDuration:             DefaultSessionDuration,
		ChallengeDuration:           DefaultChallengeDuration,
		InsertDbscChallenge:         DefaultInsertDbscChallenge,
		SelectRefreshAuthentication: DefaultSelectRefreshAuthentication,
		GenerateDbscChallenge:       DefaultGenerateDbscChallenge,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithPath(path string) Option {
	return func(config *Config) {
		config.Path = path
	}
}

func WithSessionDuration(sessionDuration time.Duration) Option {
	return func(config *Config) {
		config.SessionDuration = sessionDuration
	}
}

func WithChallengeDuration(challengeDuration time.Duration) Option {
	return func(config *Config) {
		config.ChallengeDuration = challengeDuration
	}
}

func WithInsertDbscChallenge(
	insertDbscChallenge func(ctx context.Context, challenge string, authenticationId string, challengeDuration time.Duration, db *sql.DB) error,
) Option {
	return func(config *Config) {
		config.InsertDbscChallenge = insertDbscChallenge
	}
}

func WithSelectRefreshAuthentication(
	selectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error),
) Option {
	return func(config *Config) {
		config.SelectRefreshAuthentication = selectRefreshAuthentication
	}
}

func WithGenerateDbscChallenge(generateDbscChallenge func() (string, error)) Option {
	return func(config *Config) {
		config.GenerateDbscChallenge = generateDbscChallenge
	}
}
