package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	motmedelSqlErrors "github.com/Motmedel/utils_go/pkg/database/sql/errors"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	accountPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/account"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/authentication"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/customer"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/dbsc_challenge"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/oauth_flow"
)

const (
	authenticationInsertQuery                  = `INSERT INTO authentication (account, created_at, expires_at) VALUES ($1, $2, $3) RETURNING id;`
	authenticationSelectRefreshQuery           = `SELECT ended, expires_at, dbsc_public_key FROM authentication WHERE id = $1;`
	authenticationUpdateWithDbscPublicKeyQuery = `UPDATE authentication SET dbsc_public_key = $1 WHERE id = $2;`
	authenticationUpdateWithEndedQuery         = `UPDATE authentication SET ended = true, ended_at = now() WHERE id = $1;`
)

func InsertAuthentication(
	ctx context.Context,
	accountId string,
	expirationDuration time.Duration,
	database *sql.DB,
) (*authenticationPkg.Authentication, error) {
	if accountId == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("account id"))
	}

	if database == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(expirationDuration)

	row := database.QueryRowContext(ctx, authenticationInsertQuery, accountId, now, expiresAt)
	if row == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var authenticationId string
	if err := row.Scan(&authenticationId); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	return &authenticationPkg.Authentication{Id: authenticationId, CreatedAt: &now, ExpiresAt: &expiresAt}, nil
}

func SelectRefreshAuthentication(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error) {
	if id == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if database == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	row := database.QueryRowContext(ctx, authenticationSelectRefreshQuery, id)
	if row == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var ended bool
	var expiresAt time.Time
	var dbscPublicKey []byte
	if err := row.Scan(&ended, &expiresAt, &dbscPublicKey); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	return &authenticationPkg.Authentication{
		Id: id, Ended: ended,
		ExpiresAt:     &expiresAt,
		DbscPublicKey: dbscPublicKey,
	}, nil
}

func SelectSessionEmailAddressAccount(ctx context.Context, emailAddress string, database *sql.DB) (*accountPkg.Account, error) {
	if emailAddress == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("email address"))
	}

	if database == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	var (
		accountId    string
		locked       bool
		customerId   sql.NullString
		customerName sql.NullString
		roles        []string
	)

	row := database.QueryRowContext(
		ctx,
		`SELECT a.id, a.locked, c.id, c.name, COALESCE(a.roles, '{}'::text[]) AS roles FROM account a LEFT JOIN customer c ON c.id = a.customer WHERE a.email_address = $1;`,
		emailAddress,
	)
	if row == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("sql row"))
	}

	if err := row.Scan(&accountId, &locked, &customerId, &customerName, &roles); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	account := &accountPkg.Account{Id: accountId, EmailAddress: emailAddress, Roles: roles}
	if customerId.Valid {
		account.Customer = &customer.Customer{Id: customerId.String, Name: customerName.String}
	}

	return account, nil
}

func UpdateAuthenticationWithDbscPublicKey(ctx context.Context, id string, key []byte, database *sql.DB) error {
	if id == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if len(key) == 0 {
		return motmedelErrors.NewWithTrace(empty_error.New("dbsc public key"))
	}

	if database == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context err: %w", err)
	}

	result, err := database.ExecContext(ctx, authenticationUpdateWithDbscPublicKeyQuery, key, id)
	if err != nil {
		return motmedelErrors.NewWithTrace(
			fmt.Errorf("sql database exec context: %w", err),
		)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return motmedelErrors.NewWithTrace(
			fmt.Errorf("sql database rows affected: %w", err),
			result,
		)
	}

	if rowsAffected == 0 {
		return motmedelErrors.NewWithTrace(sql.ErrNoRows)
	}

	return nil
}

func UpdateAuthenticationWithEnded(ctx context.Context, id string, database *sql.DB) error {
	if id == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if database == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context err: %w", err)
	}

	result, err := database.ExecContext(ctx, authenticationUpdateWithEndedQuery, id)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("sql database exec: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("sql database rows affected: %w", err), result)
	}

	if rowsAffected == 0 {
		return motmedelErrors.NewWithTrace(sql.ErrNoRows)
	}

	return nil
}

const (
	oauthFlowInsertQuery = `INSERT INTO oauth_flow (state, code_verifier, redirect_url, expires_at) VALUES ($1, $2, $3, $4) RETURNING id;`
	oauthFlowDeleteQuery = `DELETE FROM oauth_flow WHERE id = $1 RETURNING state, code_verifier, expires_at, redirect_url;`
)

func InsertOauthFlow(
	ctx context.Context,
	state string,
	codeVerifier string,
	redirectUrl string,
	expirationDuration time.Duration,
	database *sql.DB,
) (*oauth_flow.Flow, error) {
	if codeVerifier == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("code verifier"))
	}

	// TODO: Use empty instance error?
	if redirectUrl == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("redirect url"))
	}

	if expirationDuration == 0 {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("expiration duration"))
	}

	if database == nil {
		return nil, motmedelErrors.NewWithTrace(motmedelSqlErrors.ErrNilSqlDatabase)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	expiresAt := time.Now().Add(expirationDuration)
	row := database.QueryRowContext(ctx, oauthFlowInsertQuery, state, codeVerifier, redirectUrl, expiresAt)
	if row == nil {
		return nil, motmedelErrors.NewWithTrace(motmedelSqlErrors.ErrNilRow)
	}

	var id string
	if err := row.Scan(&id); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err), row)
	}

	return &oauth_flow.Flow{
		Id:           id,
		State:        state,
		CodeVerifier: codeVerifier,
		RedirectUrl:  redirectUrl,
		ExpiresAt:    &expiresAt,
	}, nil
}

func PopOauthFlow(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if id == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("oauth flow id"))
	}

	if database == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("sql database"))
	}

	var flow oauth_flow.Flow

	row := database.QueryRowContext(ctx, oauthFlowDeleteQuery, id)
	if row == nil {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("sql row"))
	}

	if err := row.Scan(&flow.State, &flow.CodeVerifier, &flow.ExpiresAt, &flow.RedirectUrl); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	return &flow, nil
}

const (
	dbscChallengeInsertQuery = `INSERT INTO dbsc_challenge (challenge, authentication, expires_at) VALUES ($1, $2, $3);`
	dbscChallengeDeleteQuery = `DELETE FROM dbsc_challenge WHERE challenge = $1 AND authentication = $2 RETURNING expires_at;`
)

func InsertDbscChallenge(
	ctx context.Context,
	challenge string,
	authenticationId string,
	expirationDuration time.Duration,
	database *sql.DB,
) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context err: %w", err)
	}

	if challenge == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("dbsc challenge"))
	}

	if authenticationId == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if expirationDuration == 0 {
		return motmedelErrors.NewWithTrace(empty_error.New("expiration duration"))
	}

	if database == nil {
		return motmedelErrors.NewWithTrace(motmedelSqlErrors.ErrNilSqlDatabase)
	}

	expiresAt := time.Now().Add(expirationDuration)
	if _, err := database.ExecContext(ctx, dbscChallengeInsertQuery, []byte(challenge), authenticationId, expiresAt); err != nil {
		return motmedelErrors.NewWithTrace(
			fmt.Errorf("database exec context: %w", err),
			expiresAt,
		)
	}

	return nil
}

func PopDbscChallenge(ctx context.Context, challenge string, authenticationId string, database *sql.DB) (*dbsc_challenge.Challenge, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	var expiresAt time.Time

	row := database.QueryRowContext(ctx, dbscChallengeDeleteQuery, challenge, authenticationId)
	if row == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("sql row"))
	}

	if err := row.Scan(&expiresAt); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	return &dbsc_challenge.Challenge{
		Authentication: &authenticationPkg.Authentication{Id: authenticationId},
		Challenge:      []byte(challenge),
		ExpiresAt:      &expiresAt,
	}, nil
}
