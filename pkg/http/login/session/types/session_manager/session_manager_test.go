package session_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/numeric_date"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/authentication"
	sessionErrors "github.com/altshiftab/gcp_utils/pkg/http/login/session/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager/session_manager_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
	"github.com/DATA-DOG/go-sqlmock"
)

// mockSigner implements the NamedSigner interface for testing
type mockSigner struct {
	name    string
	privKey *ecdsa.PrivateKey
}

func newMockSigner() (*mockSigner, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &mockSigner{
		name:    "ES256",
		privKey: privKey,
	}, nil
}

func (m *mockSigner) Name() string {
	return m.name
}

func (m *mockSigner) Sign(data []byte) ([]byte, error) {
	hash := make([]byte, 32)
	copy(hash, data)
	r, s, err := ecdsa.Sign(rand.Reader, m.privKey, hash)
	if err != nil {
		return nil, err
	}
	sig := append(r.Bytes(), s.Bytes()...)
	return sig, nil
}

func TestNew(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tests := []struct {
		name         string
		signer       interface{ Name() string; Sign([]byte) ([]byte, error) }
		issuer       string
		cookieDomain string
		wantErr      bool
	}{
		{
			name:         "valid parameters",
			signer:       signer,
			issuer:       "https://auth.example.com",
			cookieDomain: "example.com",
			wantErr:      false,
		},
		{
			name:         "nil signer",
			signer:       nil,
			issuer:       "https://auth.example.com",
			cookieDomain: "example.com",
			wantErr:      true,
		},
		{
			name:         "empty issuer",
			signer:       signer,
			issuer:       "",
			cookieDomain: "example.com",
			wantErr:      true,
		},
		{
			name:         "empty cookie domain",
			signer:       signer,
			issuer:       "https://auth.example.com",
			cookieDomain: "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var manager *Manager
			var err error

			if tt.signer == nil {
				manager, err = New(nil, db, tt.issuer, tt.cookieDomain)
			} else {
				manager, err = New(tt.signer, db, tt.issuer, tt.cookieDomain)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && manager == nil {
				t.Error("New() returned nil manager")
			}
		})
	}
}

func TestNew_NilDatabase(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	_, err = New(signer, nil, "https://auth.example.com", "example.com")
	if err == nil {
		t.Error("New() expected error for nil database")
	}
}

func TestNew_WithOptions(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	customCookieName := "custom_session"
	customInitialSessionDuration := 6 * time.Hour
	customAuthenticationDuration := 48 * time.Hour

	manager, err := New(
		signer,
		db,
		"https://auth.example.com",
		"example.com",
		session_manager_config.WithCookieName(customCookieName),
		session_manager_config.WithInitialSessionDuration(customInitialSessionDuration),
		session_manager_config.WithAuthenticationDuration(customAuthenticationDuration),
	)

	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if manager.CookieName != customCookieName {
		t.Errorf("CookieName = %v, want %v", manager.CookieName, customCookieName)
	}

	if manager.InitialSessionDuration != customInitialSessionDuration {
		t.Errorf("InitialSessionDuration = %v, want %v", manager.InitialSessionDuration, customInitialSessionDuration)
	}

	if manager.AuthenticationDuration != customAuthenticationDuration {
		t.Errorf("AuthenticationDuration = %v, want %v", manager.AuthenticationDuration, customAuthenticationDuration)
	}
}

func TestManager_RefreshSession(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	manager, err := New(signer, db, "https://auth.example.com", "example.com")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	now := time.Now()
	futureTime := now.Add(24 * time.Hour)
	pastTime := now.Add(-1 * time.Hour)

	validClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Id:        "auth-123:session-456",
			Subject:   "user-789:user@example.com",
			ExpiresAt: numeric_date.New(futureTime),
			NotBefore: numeric_date.New(now),
			IssuedAt:  numeric_date.New(now),
			Issuer:    "https://auth.example.com",
		},
		AuthenticationMethods: []string{"ext"},
	}

	validToken := &session_token.Token{
		Claims:           validClaims,
		AuthenticationId: "auth-123",
		SessionId:        "session-456",
	}

	tests := []struct {
		name                 string
		authentication       *authenticationPkg.Authentication
		sessionToken         *session_token.Token
		authenticationMethod string
		sessionDuration      time.Duration
		wantErr              bool
		wantErrType          error
	}{
		{
			name: "successful refresh",
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     false,
				ExpiresAt: &futureTime,
			},
			sessionToken:         validToken,
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              false,
		},
		{
			name:                 "nil authentication",
			authentication:       nil,
			sessionToken:         validToken,
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
		},
		{
			name: "nil session token",
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     false,
				ExpiresAt: &futureTime,
			},
			sessionToken:         nil,
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
		},
		{
			name: "empty authentication method",
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     false,
				ExpiresAt: &futureTime,
			},
			sessionToken:         validToken,
			authenticationMethod: "",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
		},
		{
			name: "ended authentication",
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     true,
				ExpiresAt: &futureTime,
			},
			sessionToken:         validToken,
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
			wantErrType:          sessionErrors.ErrEndedAuthentication,
		},
		{
			name: "expired authentication",
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     false,
				ExpiresAt: &pastTime,
			},
			sessionToken:         validToken,
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
			wantErrType:          sessionErrors.ErrExpiredAuthentication,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, responseError := manager.RefreshSession(
				tt.authentication,
				tt.sessionToken,
				tt.authenticationMethod,
				tt.sessionDuration,
			)

			if (responseError != nil) != tt.wantErr {
				t.Errorf("RefreshSession() error = %v, wantErr %v", responseError, tt.wantErr)
				return
			}

			if tt.wantErrType != nil && responseError != nil {
				if responseError.ProblemDetail == nil {
					t.Error("RefreshSession() expected ProblemDetail for known error type")
				}
			}

			if !tt.wantErr && response == nil {
				t.Error("RefreshSession() returned nil response")
			}

			if !tt.wantErr && response != nil {
				// Verify Set-Cookie header is present
				hasCookie := false
				for _, header := range response.Headers {
					if header.Name == "Set-Cookie" {
						hasCookie = true
						break
					}
				}
				if !hasCookie {
					t.Error("RefreshSession() response missing Set-Cookie header")
				}
			}
		})
	}
}

func TestManager_RefreshSession_NilSigner(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	// Create manager with valid signer first, then set it to nil
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	manager, err := New(signer, db, "https://auth.example.com", "example.com")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set signer to nil to test validation
	manager.Signer = nil

	now := time.Now()
	futureTime := now.Add(24 * time.Hour)

	validClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Id:        "auth-123:session-456",
			Subject:   "user-789:user@example.com",
			ExpiresAt: numeric_date.New(futureTime),
			NotBefore: numeric_date.New(now),
			IssuedAt:  numeric_date.New(now),
		},
		AuthenticationMethods: []string{"ext"},
	}

	validToken := &session_token.Token{
		Claims:           validClaims,
		AuthenticationId: "auth-123",
		SessionId:        "session-456",
	}

	authentication := &authenticationPkg.Authentication{
		Id:        "auth-123",
		Ended:     false,
		ExpiresAt: &futureTime,
	}

	_, responseError := manager.RefreshSession(authentication, validToken, "rtoken", 1*time.Hour)
	if responseError == nil {
		t.Error("RefreshSession() expected error for nil signer")
	}
}

func TestManager_Defaults(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	manager, err := New(signer, db, "https://auth.example.com", "example.com")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Check default values
	if manager.CookieName != session_manager_config.DefaultCookieName {
		t.Errorf("CookieName = %v, want %v", manager.CookieName, session_manager_config.DefaultCookieName)
	}

	if manager.InitialSessionDuration != session_manager_config.DefaultInitialSessionDuration {
		t.Errorf("InitialSessionDuration = %v, want %v", manager.InitialSessionDuration, session_manager_config.DefaultInitialSessionDuration)
	}

	if manager.AuthenticationDuration != session_manager_config.DefaultAuthenticationDuration {
		t.Errorf("AuthenticationDuration = %v, want %v", manager.AuthenticationDuration, session_manager_config.DefaultAuthenticationDuration)
	}
}

func TestManager_CreateSession_EmptyEmailAddress(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	manager, err := New(signer, db, "https://auth.example.com", "example.com")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, responseError := manager.CreateSession(nil, "")
	if responseError == nil {
		t.Error("CreateSession() expected error for empty email address")
	}
}

func TestManager_CreateSession_NilSigner(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	manager, err := New(signer, db, "https://auth.example.com", "example.com")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set signer to nil to test validation
	manager.Signer = nil

	_, responseError := manager.CreateSession(nil, "user@example.com")
	if responseError == nil {
		t.Error("CreateSession() expected error for nil signer")
	}
}

func TestManager_CreateSession_EmptyDbscAlgs(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	manager, err := New(signer, db, "https://auth.example.com", "example.com")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set DbscAlgs to empty to test validation
	manager.DbscAlgs = []string{}

	_, responseError := manager.CreateSession(nil, "user@example.com")
	if responseError == nil {
		t.Error("CreateSession() expected error for empty DbscAlgs")
	}
}

func TestManager_CreateSession_EmptyDbscRegisterPath(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("failed to create mock signer: %v", err)
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	manager, err := New(signer, db, "https://auth.example.com", "example.com")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set DbscRegisterPath to empty to test validation
	manager.DbscRegisterPath = ""

	_, responseError := manager.CreateSession(nil, "user@example.com")
	if responseError == nil {
		t.Error("CreateSession() expected error for empty DbscRegisterPath")
	}
}

func TestSessionErrors(t *testing.T) {
	// Verify error definitions
	if sessionErrors.ErrEndedAuthentication == nil {
		t.Error("ErrEndedAuthentication is nil")
	}

	if sessionErrors.ErrExpiredAuthentication == nil {
		t.Error("ErrExpiredAuthentication is nil")
	}

	// Verify errors are different
	if errors.Is(sessionErrors.ErrEndedAuthentication, sessionErrors.ErrExpiredAuthentication) {
		t.Error("ErrEndedAuthentication should not be ErrExpiredAuthentication")
	}
}
