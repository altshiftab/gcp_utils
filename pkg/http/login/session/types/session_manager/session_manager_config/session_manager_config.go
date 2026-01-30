package session_manager_config

import (
	"context"
	"database/sql"
	"time"

	"github.com/altshiftab/gcp_utils/pkg/http/login/database"
	accountPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/account"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/authentication"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
)

var (
	DefaultCookieName = "session"
	// TODO: This could change as DBSC becomes more mature?
	DefaultInitialSessionDuration = 12 * time.Hour
	DefaultAuthenticationDuration = 24 * 7 * time.Hour
	DefaultDbscChallengeDuration  = dbsc_refresh_endpoint_config.DefaultChallengeDuration
	DefaultDbscRegisterPath       = dbsc_register_endpoint_config.DefaultPath
	DefaultDbscAlgs               = []string{"ES256"}

	DefaultSelectSessionEmailAddressAccount = database.SelectSessionEmailAddressAccount
	DefaultInsertAuthentication             = database.InsertAuthentication
	DefaultInsertDbscChallenge              = database.InsertDbscChallenge
)

type Config struct {
	CookieName                       string
	InitialSessionDuration           time.Duration
	AuthenticationDuration           time.Duration
	DbscChallengeDuration            time.Duration
	DbscRegisterPath                 string
	DbscAlgs                         []string
	SelectSessionEmailAddressAccount func(ctx context.Context, emailAddress string, database *sql.DB) (*accountPkg.Account, error)
	InsertAuthentication             func(ctx context.Context, accountId string, expirationDuration time.Duration, database *sql.DB) (*authenticationPkg.Authentication, error)
	InsertDbscChallenge              func(ctx context.Context, challenge string, authenticationId string, expirationDuration time.Duration, db *sql.DB) error
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CookieName:                       DefaultCookieName,
		InitialSessionDuration:           DefaultInitialSessionDuration,
		AuthenticationDuration:           DefaultAuthenticationDuration,
		DbscChallengeDuration:            DefaultDbscChallengeDuration,
		DbscRegisterPath:                 DefaultDbscRegisterPath,
		DbscAlgs:                         DefaultDbscAlgs,
		SelectSessionEmailAddressAccount: DefaultSelectSessionEmailAddressAccount,
		InsertAuthentication:             DefaultInsertAuthentication,
		InsertDbscChallenge:              DefaultInsertDbscChallenge,
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

func WithInitialSessionDuration(initialSessionDuration time.Duration) Option {
	return func(config *Config) {
		config.InitialSessionDuration = initialSessionDuration
	}
}

func WithAuthenticationDuration(authenticationDuration time.Duration) Option {
	return func(config *Config) {
		config.AuthenticationDuration = authenticationDuration
	}
}

func WithDbscChallengeDuration(dbscChallengeDuration time.Duration) Option {
	return func(config *Config) {
		config.DbscChallengeDuration = dbscChallengeDuration
	}
}

func WithDbscRegisterPath(dbscRegisterPath string) Option {
	return func(config *Config) {
		config.DbscRegisterPath = dbscRegisterPath
	}
}

func WithDbscAlgs(dbscAlgs []string) Option {
	return func(config *Config) {
		config.DbscAlgs = dbscAlgs
	}
}

func WithSelectSessionEmailAddressAccount(selectSessionEmailAddressAccount func(ctx context.Context, emailAddress string, database *sql.DB) (*accountPkg.Account, error)) Option {
	return func(config *Config) {
		config.SelectSessionEmailAddressAccount = selectSessionEmailAddressAccount
	}
}

func WithInsertAuthentication(insertAuthentication func(ctx context.Context, accountId string, expirationDuration time.Duration, database *sql.DB) (*authenticationPkg.Authentication, error)) Option {
	return func(config *Config) {
		config.InsertAuthentication = insertAuthentication
	}
}

func WithInsertDbscChallenge(insertDbscChallenge func(ctx context.Context, challenge string, authenticationId string, expirationDuration time.Duration, db *sql.DB) error) Option {
	return func(config *Config) {
		config.InsertDbscChallenge = insertDbscChallenge
	}
}
