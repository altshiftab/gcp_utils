package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestInsertAuthentication(t *testing.T) {
	tests := []struct {
		name               string
		accountId          string
		expirationDuration time.Duration
		setupMock          func(mock sqlmock.Sqlmock)
		wantErr            bool
		checkResult        func(t *testing.T, auth interface{}, err error)
	}{
		{
			name:               "successful insert",
			accountId:          "account-123",
			expirationDuration: 24 * time.Hour,
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id"}).AddRow("auth-456")
				mock.ExpectQuery(`INSERT INTO authentication`).
					WithArgs("account-123", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr: false,
			checkResult: func(t *testing.T, auth interface{}, err error) {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			},
		},
		{
			name:               "empty account id",
			accountId:          "",
			expirationDuration: 24 * time.Hour,
			setupMock:          func(mock sqlmock.Sqlmock) {},
			wantErr:            true,
		},
		{
			name:               "database error",
			accountId:          "account-123",
			expirationDuration: 24 * time.Hour,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`INSERT INTO authentication`).
					WithArgs("account-123", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("database error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			auth, err := InsertAuthentication(context.Background(), tt.accountId, tt.expirationDuration, db)

			if (err != nil) != tt.wantErr {
				t.Errorf("InsertAuthentication() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.checkResult != nil {
				tt.checkResult(t, auth, err)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestInsertAuthentication_NilDatabase(t *testing.T) {
	_, err := InsertAuthentication(context.Background(), "account-123", 24*time.Hour, nil)
	if err == nil {
		t.Error("expected error for nil database")
	}
}

func TestInsertAuthentication_CanceledContext(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = InsertAuthentication(ctx, "account-123", 24*time.Hour, db)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestSelectRefreshAuthentication(t *testing.T) {
	futureTime := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name      string
		id        string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "successful select",
			id:   "auth-123",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"ended", "expires_at", "dbsc_public_key"}).
					AddRow(false, futureTime, []byte("public-key"))
				mock.ExpectQuery(`SELECT ended, expires_at, dbsc_public_key FROM authentication`).
					WithArgs("auth-123").
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name:      "empty id",
			id:        "",
			setupMock: func(mock sqlmock.Sqlmock) {},
			wantErr:   true,
		},
		{
			name: "not found",
			id:   "auth-notfound",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT ended, expires_at, dbsc_public_key FROM authentication`).
					WithArgs("auth-notfound").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			_, err = SelectRefreshAuthentication(context.Background(), tt.id, db)

			if (err != nil) != tt.wantErr {
				t.Errorf("SelectRefreshAuthentication() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestSelectRefreshAuthentication_NilDatabase(t *testing.T) {
	_, err := SelectRefreshAuthentication(context.Background(), "auth-123", nil)
	if err == nil {
		t.Error("expected error for nil database")
	}
}

func TestSelectSessionEmailAddressAccount(t *testing.T) {
	tests := []struct {
		name         string
		emailAddress string
		setupMock    func(mock sqlmock.Sqlmock)
		wantErr      bool
	}{
		{
			name:         "successful select with customer",
			emailAddress: "user@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "locked", "customer_id", "customer_name", "roles"}).
					AddRow("account-123", false, "customer-456", "Acme Corp", []string{"admin"})
				mock.ExpectQuery(`SELECT a.id, a.locked, c.id, c.name, COALESCE`).
					WithArgs("user@example.com").
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name:         "successful select without customer",
			emailAddress: "user@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "locked", "customer_id", "customer_name", "roles"}).
					AddRow("account-123", false, nil, nil, []string{})
				mock.ExpectQuery(`SELECT a.id, a.locked, c.id, c.name, COALESCE`).
					WithArgs("user@example.com").
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name:         "empty email address",
			emailAddress: "",
			setupMock:    func(mock sqlmock.Sqlmock) {},
			wantErr:      true,
		},
		{
			name:         "not found",
			emailAddress: "notfound@example.com",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT a.id, a.locked, c.id, c.name, COALESCE`).
					WithArgs("notfound@example.com").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			_, err = SelectSessionEmailAddressAccount(context.Background(), tt.emailAddress, db)

			if (err != nil) != tt.wantErr {
				t.Errorf("SelectSessionEmailAddressAccount() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestSelectSessionEmailAddressAccount_NilDatabase(t *testing.T) {
	_, err := SelectSessionEmailAddressAccount(context.Background(), "user@example.com", nil)
	if err == nil {
		t.Error("expected error for nil database")
	}
}

func TestUpdateAuthenticationWithDbscPublicKey(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		key       []byte
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "successful update",
			id:   "auth-123",
			key:  []byte("public-key-data"),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`UPDATE authentication SET dbsc_public_key`).
					WithArgs([]byte("public-key-data"), "auth-123").
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantErr: false,
		},
		{
			name:      "empty id",
			id:        "",
			key:       []byte("public-key-data"),
			setupMock: func(mock sqlmock.Sqlmock) {},
			wantErr:   true,
		},
		{
			name:      "empty key",
			id:        "auth-123",
			key:       []byte{},
			setupMock: func(mock sqlmock.Sqlmock) {},
			wantErr:   true,
		},
		{
			name: "no rows affected",
			id:   "auth-notfound",
			key:  []byte("public-key-data"),
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`UPDATE authentication SET dbsc_public_key`).
					WithArgs([]byte("public-key-data"), "auth-notfound").
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			err = UpdateAuthenticationWithDbscPublicKey(context.Background(), tt.id, tt.key, db)

			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateAuthenticationWithDbscPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestUpdateAuthenticationWithDbscPublicKey_NilDatabase(t *testing.T) {
	err := UpdateAuthenticationWithDbscPublicKey(context.Background(), "auth-123", []byte("key"), nil)
	if err == nil {
		t.Error("expected error for nil database")
	}
}

func TestUpdateAuthenticationWithEnded(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "successful update",
			id:   "auth-123",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`UPDATE authentication SET ended = true`).
					WithArgs("auth-123").
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantErr: false,
		},
		{
			name:      "empty id",
			id:        "",
			setupMock: func(mock sqlmock.Sqlmock) {},
			wantErr:   true,
		},
		{
			name: "no rows affected",
			id:   "auth-notfound",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`UPDATE authentication SET ended = true`).
					WithArgs("auth-notfound").
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			err = UpdateAuthenticationWithEnded(context.Background(), tt.id, db)

			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateAuthenticationWithEnded() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestUpdateAuthenticationWithEnded_NilDatabase(t *testing.T) {
	err := UpdateAuthenticationWithEnded(context.Background(), "auth-123", nil)
	if err == nil {
		t.Error("expected error for nil database")
	}
}

func TestInsertOauthFlow(t *testing.T) {
	tests := []struct {
		name               string
		state              string
		codeVerifier       string
		redirectUrl        string
		expirationDuration time.Duration
		setupMock          func(mock sqlmock.Sqlmock)
		wantErr            bool
	}{
		{
			name:               "successful insert",
			state:              "state-123",
			codeVerifier:       "verifier-456",
			redirectUrl:        "https://example.com/callback",
			expirationDuration: 10 * time.Minute,
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id"}).AddRow("flow-789")
				mock.ExpectQuery(`INSERT INTO oauth_flow`).
					WithArgs("state-123", "verifier-456", "https://example.com/callback", sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name:               "empty code verifier",
			state:              "state-123",
			codeVerifier:       "",
			redirectUrl:        "https://example.com/callback",
			expirationDuration: 10 * time.Minute,
			setupMock:          func(mock sqlmock.Sqlmock) {},
			wantErr:            true,
		},
		{
			name:               "empty redirect url",
			state:              "state-123",
			codeVerifier:       "verifier-456",
			redirectUrl:        "",
			expirationDuration: 10 * time.Minute,
			setupMock:          func(mock sqlmock.Sqlmock) {},
			wantErr:            true,
		},
		{
			name:               "zero expiration duration",
			state:              "state-123",
			codeVerifier:       "verifier-456",
			redirectUrl:        "https://example.com/callback",
			expirationDuration: 0,
			setupMock:          func(mock sqlmock.Sqlmock) {},
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			_, err = InsertOauthFlow(context.Background(), tt.state, tt.codeVerifier, tt.redirectUrl, tt.expirationDuration, db)

			if (err != nil) != tt.wantErr {
				t.Errorf("InsertOauthFlow() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestInsertOauthFlow_NilDatabase(t *testing.T) {
	_, err := InsertOauthFlow(context.Background(), "state", "verifier", "https://example.com", 10*time.Minute, nil)
	if err == nil {
		t.Error("expected error for nil database")
	}
}

func TestPopOauthFlow(t *testing.T) {
	futureTime := time.Now().Add(10 * time.Minute)

	tests := []struct {
		name      string
		id        string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "successful pop",
			id:   "flow-123",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"state", "code_verifier", "expires_at", "redirect_url"}).
					AddRow("state-456", "verifier-789", futureTime, "https://example.com/callback")
				mock.ExpectQuery(`DELETE FROM oauth_flow WHERE id`).
					WithArgs("flow-123").
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name:      "empty id",
			id:        "",
			setupMock: func(mock sqlmock.Sqlmock) {},
			wantErr:   true,
		},
		{
			name: "not found",
			id:   "flow-notfound",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`DELETE FROM oauth_flow WHERE id`).
					WithArgs("flow-notfound").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			_, err = PopOauthFlow(context.Background(), tt.id, db)

			if (err != nil) != tt.wantErr {
				t.Errorf("PopOauthFlow() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestPopOauthFlow_NilDatabase(t *testing.T) {
	_, err := PopOauthFlow(context.Background(), "flow-123", nil)
	if err == nil {
		t.Error("expected error for nil database")
	}
}

func TestInsertDbscChallenge(t *testing.T) {
	tests := []struct {
		name               string
		challenge          string
		authenticationId   string
		expirationDuration time.Duration
		setupMock          func(mock sqlmock.Sqlmock)
		wantErr            bool
	}{
		{
			name:               "successful insert",
			challenge:          "challenge-123",
			authenticationId:   "auth-456",
			expirationDuration: 5 * time.Minute,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`INSERT INTO dbsc_challenge`).
					WithArgs([]byte("challenge-123"), "auth-456", sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantErr: false,
		},
		{
			name:               "empty challenge",
			challenge:          "",
			authenticationId:   "auth-456",
			expirationDuration: 5 * time.Minute,
			setupMock:          func(mock sqlmock.Sqlmock) {},
			wantErr:            true,
		},
		{
			name:               "empty authentication id",
			challenge:          "challenge-123",
			authenticationId:   "",
			expirationDuration: 5 * time.Minute,
			setupMock:          func(mock sqlmock.Sqlmock) {},
			wantErr:            true,
		},
		{
			name:               "zero expiration duration",
			challenge:          "challenge-123",
			authenticationId:   "auth-456",
			expirationDuration: 0,
			setupMock:          func(mock sqlmock.Sqlmock) {},
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			err = InsertDbscChallenge(context.Background(), tt.challenge, tt.authenticationId, tt.expirationDuration, db)

			if (err != nil) != tt.wantErr {
				t.Errorf("InsertDbscChallenge() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestInsertDbscChallenge_NilDatabase(t *testing.T) {
	err := InsertDbscChallenge(context.Background(), "challenge", "auth-123", 5*time.Minute, nil)
	if err == nil {
		t.Error("expected error for nil database")
	}
}

func TestPopDbscChallenge(t *testing.T) {
	futureTime := time.Now().Add(5 * time.Minute)

	tests := []struct {
		name             string
		challenge        string
		authenticationId string
		setupMock        func(mock sqlmock.Sqlmock)
		wantErr          bool
	}{
		{
			name:             "successful pop",
			challenge:        "challenge-123",
			authenticationId: "auth-456",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"expires_at"}).AddRow(futureTime)
				mock.ExpectQuery(`DELETE FROM dbsc_challenge WHERE challenge`).
					WithArgs("challenge-123", "auth-456").
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name:             "not found",
			challenge:        "challenge-notfound",
			authenticationId: "auth-456",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`DELETE FROM dbsc_challenge WHERE challenge`).
					WithArgs("challenge-notfound", "auth-456").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			_, err = PopDbscChallenge(context.Background(), tt.challenge, tt.authenticationId, db)

			if (err != nil) != tt.wantErr {
				t.Errorf("PopDbscChallenge() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}
