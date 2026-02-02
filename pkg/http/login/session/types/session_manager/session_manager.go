package session_manager

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelDatabase "github.com/Motmedel/utils_go/pkg/database"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/numeric_date"
	motmedelTime "github.com/Motmedel/utils_go/pkg/time"
	"github.com/Motmedel/utils_go/pkg/utils"
	accountPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/account"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/authentication"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session"
	sessionErrors "github.com/altshiftab/gcp_utils/pkg/http/login/session/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authentication_method"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_cookie"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager/session_manager_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
	"github.com/google/uuid"
)

type Manager struct {
	Signer       motmedelCryptoInterfaces.NamedSigner
	Issuer       string
	CookieDomain string
	Db           *sql.DB

	CookieName                string
	InitialSessionDuration    time.Duration
	AuthenticationDuration    time.Duration
	DbscChallengeDuration     time.Duration
	DbscRegisterPath          string
	DbscAlgs                  []string
	selectEmailAddressAccount func(ctx context.Context, emailAddress string, database *sql.DB) (*accountPkg.Account, error)
	insertAuthentication      func(ctx context.Context, accountId string, expirationDuration time.Duration, database *sql.DB) (*authenticationPkg.Authentication, error)
	insertDbscChallenge       func(ctx context.Context, challenge string, authenticationId string, expirationDuration time.Duration, db *sql.DB) error
}

func (m *Manager) CreateSession(ctx context.Context, emailAddress string) (*response.Response, *response_error.ResponseError) {
	signer := m.Signer
	if utils.IsNil(signer) {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("signer")),
		}
	}

	dbscAlgs := m.DbscAlgs
	if len(dbscAlgs) == 0 {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("dbsc algs")),
		}
	}

	dbscRegisterPath := m.DbscRegisterPath
	if dbscRegisterPath == "" {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("dbsc register path")),
		}
	}

	audience := m.CookieDomain
	if audience == "" {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("audience (cookie domain)")),
		}
	}

	if emailAddress == "" {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("email address")),
		}
	}

	selectAccountCtx, selectAccountCtxCancel := motmedelDatabase.MakeTimeoutCtx(ctx)
	defer selectAccountCtxCancel()
	account, err := m.selectEmailAddressAccount(selectAccountCtx, emailAddress, m.Db)
	wrappedErr := motmedelErrors.New(fmt.Errorf("select email address account: %w", err), emailAddress)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("The email address is not associated with an account."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if account == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("account")),
		}
	}
	accountId := account.Id
	if accountId == "" {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("account id")),
		}
	}

	accountEmailAddress := account.EmailAddress
	if accountEmailAddress == "" {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication account email address")),
		}
	}

	var authorizedParty string
	customer := account.Customer
	if customer != nil {
		customerId := customer.Id
		if customerId == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication account customer id")),
			}
		}

		customerName := customer.Name
		if customerName == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication account customer name")),
			}
		}

		authorizedParty = strings.Join([]string{customerId, customerName}, ":")
	}

	if account.Locked {
		return nil, &response_error.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusForbidden,
				problem_detail_config.WithDetail("The account is locked."),
			),
		}
	}

	// TODO: Insert name?
	// TODO: Extract IP address, user agent from context (http context)

	insertDbCtx, insertDbCancel := motmedelDatabase.MakeTimeoutCtx(ctx)
	defer insertDbCancel()

	authentication, err := m.insertAuthentication(insertDbCtx, accountId, m.AuthenticationDuration, m.Db)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("insert authentication: %w", err)),
		}
	}
	if authentication == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authentication")),
		}
	}

	authenticationId := authentication.Id
	if authenticationId == "" {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication id")),
		}
	}

	dbscChallenge, err := session.GenerateDbscChallenge()
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("generate dbsc challenge: %w", err)),
		}
	}
	if dbscChallenge == "" {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("dbsc challenge")),
		}
	}

	dbInsertCtx, dbInsertCtxCancel := motmedelDatabase.MakeTimeoutCtx(ctx)
	defer dbInsertCtxCancel()
	err = m.insertDbscChallenge(dbInsertCtx, dbscChallenge, authenticationId, m.DbscChallengeDuration, m.Db)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(
				fmt.Errorf("insert dbsc challenge: %w", err),
				authenticationId,
				dbscChallenge,
			),
		}
	}

	authenticationExpiresAt := authentication.ExpiresAt
	if authenticationExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authentication expires at")),
		}
	}

	authenticationCreatedAt := authentication.CreatedAt
	if authenticationCreatedAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authentication created at")),
		}
	}

	issuedAt := numeric_date.New(time.Now())

	sessionExpiresAtCandidate := time.Now().Add(m.InitialSessionDuration)
	sessionExpiresAt := motmedelTime.Min(&sessionExpiresAtCandidate, authenticationExpiresAt)
	if sessionExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session expires at")),
		}
	}

	audienceClaimString, err := claim_strings.Convert(audience)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("claim strings convert: %w", err), audience),
		}
	}

	sessionClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Id:        strings.Join([]string{authenticationId, uuid.New().String()}, ":"),
			Issuer:    m.Issuer,
			Audience:  audienceClaimString,
			Subject:   strings.Join([]string{accountId, accountEmailAddress}, ":"),
			ExpiresAt: numeric_date.New(*sessionExpiresAt),
			NotBefore: issuedAt,
			IssuedAt:  issuedAt,
		},
		AuthenticationMethods: []string{authentication_method.Sso},
		AuthenticatedAt:       numeric_date.New(*authenticationCreatedAt),
		AuthorizedParty:       authorizedParty,
		Roles:                 account.Roles,
	}
	sessionToken, err := session_token.Parse(sessionClaims)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("session token parse: %w", err), sessionClaims),
		}
	}
	if sessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session token")),
		}
	}

	sessionTokenString, err := sessionToken.Encode(m.Signer)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(
				fmt.Errorf("new session token encode: %w", err),
				sessionToken, signer,
			),
		}
	}

	sessionCookie, err := session_cookie.New(
		sessionTokenString,
		*sessionExpiresAt,
		m.CookieName,
		m.CookieDomain,
	)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(
				fmt.Errorf("session cookie new: %w", err),
				sessionTokenString, sessionExpiresAt, m.CookieName, m.CookieDomain,
			),
		}
	}
	if sessionCookie == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session cookie")),
		}
	}

	return &response.Response{
		Headers: []*response.HeaderEntry{
			{
				Name:  "Set-Cookie",
				Value: sessionCookie.String(),
			},
			{
				Name: "Sec-Session-Registration",
				Value: fmt.Sprintf(
					"(%s); path=\"%s\"; challenge=\"%s\"",
					strings.Join(dbscAlgs, " "),
					dbscRegisterPath,
					dbscChallenge,
				),
			},
		},
	}, nil
}

func (m *Manager) RefreshSession(
	authentication *authenticationPkg.Authentication,
	sessionToken *session_token.Token,
	authenticationMethod string,
	sessionDuration time.Duration,
) (*response.Response, *response_error.ResponseError) {
	if authentication == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authentication")),
		}
	}

	if sessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session token")),
		}
	}

	if authenticationMethod == "" {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication method")),
		}
	}

	signer := m.Signer
	if utils.IsNil(signer) {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("signer")),
		}
	}

	newSessionToken, err := sessionToken.Refresh(authentication, sessionDuration, authenticationMethod)
	if err != nil {
		if errors.Is(err, sessionErrors.ErrEndedAuthentication) {
			return nil, &response_error.ResponseError{
				Headers: []*response.HeaderEntry{{Name: "Clear-Site-Data", Value: `"cookies"`}},
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session's authentication has ended."),
				),
			}
		} else if errors.Is(err, sessionErrors.ErrExpiredAuthentication) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session's authentication has expired."),
				),
			}
		}

		return nil, &response_error.ResponseError{ServerError: fmt.Errorf("session token refresh: %w", err)}
	}
	if newSessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("new session token")),
		}
	}

	newSessionTokenClaims := newSessionToken.Claims
	if newSessionTokenClaims == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("new session token claims")),
		}
	}
	newSessionTokenExpiresAt := newSessionTokenClaims.ExpiresAt
	if newSessionTokenExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("new session token claims expires at")),
		}
	}

	newSessionTokenString, err := newSessionToken.Encode(signer)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(
				fmt.Errorf("new session token encode: %w", err),
				newSessionToken, signer,
			),
		}
	}

	sessionCookie, err := session_cookie.New(
		newSessionTokenString,
		newSessionTokenExpiresAt.Time,
		m.CookieName,
		m.CookieDomain,
	)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(
				fmt.Errorf("session cookie new: %w", err),
				newSessionTokenString, newSessionTokenExpiresAt.Time, m.CookieName, m.CookieDomain,
			),
		}
	}
	if sessionCookie == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session cookie")),
		}
	}

	return &response.Response{
		Headers: []*response.HeaderEntry{{Name: "Set-Cookie", Value: sessionCookie.String()}},
	}, nil
}

func New(
	signer motmedelCryptoInterfaces.NamedSigner,
	db *sql.DB,
	issuer string,
	cookieDomain string,
	options ...session_manager_config.Option,
) (*Manager, error) {
	if utils.IsNil(signer) {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("signer"))
	}

	if db == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("db"))
	}

	if issuer == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("issuer"))
	}

	if cookieDomain == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("cookie domain"))
	}

	config := session_manager_config.New(options...)

	return &Manager{
		Signer:                    signer,
		Db:                        db,
		CookieDomain:              cookieDomain,
		CookieName:                config.CookieName,
		InitialSessionDuration:    config.InitialSessionDuration,
		AuthenticationDuration:    config.AuthenticationDuration,
		DbscChallengeDuration:     config.DbscChallengeDuration,
		DbscRegisterPath:          config.DbscRegisterPath,
		DbscAlgs:                  config.DbscAlgs,
		selectEmailAddressAccount: config.SelectEmailAddressAccount,
		insertAuthentication:      config.InsertAuthentication,
		insertDbscChallenge:       config.InsertDbscChallenge,
	}, nil
}
