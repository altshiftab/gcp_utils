package session_token

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
)

func TestParse(t *testing.T) {
	tests := []struct {
		name                    string
		claims                  *session_claims.Claims
		wantAuthenticationId    string
		wantSessionId           string
		wantSubjectId           string
		wantSubjectEmailAddress string
		wantTenantId            string
		wantTenantName          string
		wantErr                 bool
	}{
		{
			name:    "nil claims",
			claims:  nil,
			wantErr: false,
		},
		{
			name: "valid claims with all fields",
			claims: &session_claims.Claims{
				Claims: registered_claims.Claims{
					Id:      "auth-123:session-456",
					Subject: "user-789:user@example.com",
				},
				AuthorizedParty: "tenant-001:Acme Corp",
			},
			wantAuthenticationId:    "auth-123",
			wantSessionId:           "session-456",
			wantSubjectId:           "user-789",
			wantSubjectEmailAddress: "user@example.com",
			wantTenantId:            "tenant-001",
			wantTenantName:          "Acme Corp",
			wantErr:                 false,
		},
		{
			name: "claims without authorized party",
			claims: &session_claims.Claims{
				Claims: registered_claims.Claims{
					Id:      "auth-123:session-456",
					Subject: "user-789:user@example.com",
				},
			},
			wantAuthenticationId:    "auth-123",
			wantSessionId:           "session-456",
			wantSubjectId:           "user-789",
			wantSubjectEmailAddress: "user@example.com",
			wantTenantId:            "",
			wantTenantName:          "",
			wantErr:                 false,
		},
		{
			name: "claims with empty id",
			claims: &session_claims.Claims{
				Claims: registered_claims.Claims{
					Id:      "",
					Subject: "user-789:user@example.com",
				},
			},
			wantAuthenticationId:    "",
			wantSessionId:           "",
			wantSubjectId:           "user-789",
			wantSubjectEmailAddress: "user@example.com",
			wantErr:                 false,
		},
		{
			name: "claims with invalid id format (no colon)",
			claims: &session_claims.Claims{
				Claims: registered_claims.Claims{
					Id:      "invalid-id-no-colon",
					Subject: "user-789:user@example.com",
				},
			},
			wantErr: true,
		},
		{
			name: "claims with invalid subject format (no colon)",
			claims: &session_claims.Claims{
				Claims: registered_claims.Claims{
					Id:      "auth-123:session-456",
					Subject: "invalid-subject-no-colon",
				},
			},
			wantErr: true,
		},
		{
			name: "claims with invalid azp format (no colon)",
			claims: &session_claims.Claims{
				Claims: registered_claims.Claims{
					Id:      "auth-123:session-456",
					Subject: "user-789:user@example.com",
				},
				AuthorizedParty: "invalid-azp-no-colon",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := Parse(tt.claims)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if tt.claims == nil {
				if token != nil {
					t.Error("Parse() expected nil token for nil claims")
				}
				return
			}

			if token == nil {
				t.Fatal("Parse() returned nil token for non-nil claims")
			}

			if token.AuthenticationId != tt.wantAuthenticationId {
				t.Errorf("Parse() AuthenticationId = %v, want %v", token.AuthenticationId, tt.wantAuthenticationId)
			}
			if token.SessionId != tt.wantSessionId {
				t.Errorf("Parse() SessionId = %v, want %v", token.SessionId, tt.wantSessionId)
			}
			if token.SubjectId != tt.wantSubjectId {
				t.Errorf("Parse() SubjectId = %v, want %v", token.SubjectId, tt.wantSubjectId)
			}
			if token.SubjectEmailAddress != tt.wantSubjectEmailAddress {
				t.Errorf("Parse() SubjectEmailAddress = %v, want %v", token.SubjectEmailAddress, tt.wantSubjectEmailAddress)
			}
			if token.TenantId != tt.wantTenantId {
				t.Errorf("Parse() TenantId = %v, want %v", token.TenantId, tt.wantTenantId)
			}
			if token.TenantName != tt.wantTenantName {
				t.Errorf("Parse() TenantName = %v, want %v", token.TenantName, tt.wantTenantName)
			}
		})
	}
}

func TestToken_GetUser(t *testing.T) {
	tests := []struct {
		name       string
		token      *Token
		wantId     string
		wantEmail  string
		wantGroup  bool
		wantRoles  []string
	}{
		{
			name: "token with all fields",
			token: &Token{
				SubjectId:           "user-123",
				SubjectEmailAddress: "user@example.com",
				TenantId:            "tenant-001",
				TenantName:          "Acme Corp",
				Roles:               []string{"admin", "user"},
			},
			wantId:    "user-123",
			wantEmail: "user@example.com",
			wantGroup: true,
			wantRoles: []string{"admin", "user"},
		},
		{
			name: "token without tenant",
			token: &Token{
				SubjectId:           "user-456",
				SubjectEmailAddress: "another@example.com",
				Roles:               []string{"viewer"},
			},
			wantId:    "user-456",
			wantEmail: "another@example.com",
			wantGroup: false,
			wantRoles: []string{"viewer"},
		},
		{
			name: "token with only tenant id",
			token: &Token{
				SubjectId:           "user-789",
				SubjectEmailAddress: "test@example.com",
				TenantId:            "tenant-002",
			},
			wantId:    "user-789",
			wantEmail: "test@example.com",
			wantGroup: true,
		},
		{
			name: "token with only tenant name",
			token: &Token{
				SubjectId:           "user-abc",
				SubjectEmailAddress: "abc@example.com",
				TenantName:          "Some Corp",
			},
			wantId:    "user-abc",
			wantEmail: "abc@example.com",
			wantGroup: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.token.GetUser()

			if user == nil {
				t.Fatal("GetUser() returned nil")
			}

			if user.Id != tt.wantId {
				t.Errorf("GetUser() Id = %v, want %v", user.Id, tt.wantId)
			}
			if user.Email != tt.wantEmail {
				t.Errorf("GetUser() Email = %v, want %v", user.Email, tt.wantEmail)
			}

			if tt.wantGroup {
				if user.Group == nil {
					t.Error("GetUser() expected Group to be set")
				}
			} else {
				if user.Group != nil {
					t.Error("GetUser() expected Group to be nil")
				}
			}
		})
	}
}

func TestToken_UserAttributes(t *testing.T) {
	t.Run("token with all fields", func(t *testing.T) {
		token := &Token{
			SubjectId:           "user-123",
			SubjectEmailAddress: "user@example.com",
			TenantId:            "tenant-001",
			TenantName:          "Acme Corp",
			Roles:               []string{"admin", "user"},
		}

		attrs := token.UserAttributes()
		if len(attrs) == 0 {
			t.Error("UserAttributes() returned empty slice")
		}
	})

	t.Run("token without roles", func(t *testing.T) {
		token := &Token{
			SubjectId:           "user-456",
			SubjectEmailAddress: "another@example.com",
		}

		attrs := token.UserAttributes()
		if len(attrs) == 0 {
			t.Error("UserAttributes() returned empty slice")
		}
	})

	t.Run("token without tenant", func(t *testing.T) {
		token := &Token{
			SubjectId:           "user-789",
			SubjectEmailAddress: "test@example.com",
			Roles:               []string{"viewer"},
		}

		attrs := token.UserAttributes()
		if len(attrs) == 0 {
			t.Error("UserAttributes() returned empty slice")
		}
	})
}

func TestToken_Refresh(t *testing.T) {
	now := time.Now()
	futureTime := now.Add(24 * time.Hour)
	pastTime := now.Add(-1 * time.Hour)

	baseClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Id:        "auth-123:session-456",
			Subject:   "user-789:user@example.com",
			ExpiresAt: numeric_date.New(futureTime),
			NotBefore: numeric_date.New(now),
			IssuedAt:  numeric_date.New(now),
		},
		AuthenticationMethods: []string{"ext"},
	}

	tests := []struct {
		name                 string
		token                *Token
		authentication       *authenticationPkg.Authentication
		authenticationMethod string
		sessionDuration      time.Duration
		wantErr              bool
		wantErrType          error
	}{
		{
			name: "successful refresh",
			token: &Token{
				Claims:           baseClaims,
				AuthenticationId: "auth-123",
				SessionId:        "session-456",
			},
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     false,
				ExpiresAt: &futureTime,
			},
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              false,
		},
		{
			name: "nil authentication",
			token: &Token{
				Claims:           baseClaims,
				AuthenticationId: "auth-123",
			},
			authentication:       nil,
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
		},
		{
			name: "empty authentication method",
			token: &Token{
				Claims:           baseClaims,
				AuthenticationId: "auth-123",
			},
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     false,
				ExpiresAt: &futureTime,
			},
			authenticationMethod: "",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
		},
		{
			name: "nil claims",
			token: &Token{
				Claims:           nil,
				AuthenticationId: "auth-123",
			},
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     false,
				ExpiresAt: &futureTime,
			},
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
		},
		{
			name: "ended authentication",
			token: &Token{
				Claims:           baseClaims,
				AuthenticationId: "auth-123",
			},
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     true,
				ExpiresAt: &futureTime,
			},
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
			wantErrType:          sessionErrors.ErrEndedAuthentication,
		},
		{
			name: "expired authentication",
			token: &Token{
				Claims:           baseClaims,
				AuthenticationId: "auth-123",
			},
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     false,
				ExpiresAt: &pastTime,
			},
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
			wantErrType:          sessionErrors.ErrExpiredAuthentication,
		},
		{
			name: "nil authentication expires at",
			token: &Token{
				Claims:           baseClaims,
				AuthenticationId: "auth-123",
			},
			authentication: &authenticationPkg.Authentication{
				Id:        "auth-123",
				Ended:     false,
				ExpiresAt: nil,
			},
			authenticationMethod: "rtoken",
			sessionDuration:      1 * time.Hour,
			wantErr:              true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newToken, err := tt.token.Refresh(tt.authentication, tt.sessionDuration, tt.authenticationMethod)

			if (err != nil) != tt.wantErr {
				t.Errorf("Refresh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErrType != nil && err != nil {
				if !errors.Is(err, tt.wantErrType) {
					t.Errorf("Refresh() error = %v, want %v", err, tt.wantErrType)
				}
			}

			if tt.wantErr {
				return
			}

			if newToken == nil {
				t.Fatal("Refresh() returned nil token")
			}

			if newToken.Claims == nil {
				t.Fatal("Refresh() returned token with nil claims")
			}

			// Verify authentication method is updated
			if len(newToken.Claims.AuthenticationMethods) != 1 || newToken.Claims.AuthenticationMethods[0] != tt.authenticationMethod {
				t.Errorf("Refresh() AuthenticationMethods = %v, want [%s]", newToken.Claims.AuthenticationMethods, tt.authenticationMethod)
			}
		})
	}
}

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
	// Simple concatenation for testing
	sig := append(r.Bytes(), s.Bytes()...)
	return sig, nil
}

func TestToken_Encode(t *testing.T) {
	signer, err := newMockSigner()
	if err != nil {
		t.Fatalf("Failed to create mock signer: %v", err)
	}

	now := time.Now()
	claims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Id:        "auth-123:session-456",
			Subject:   "user-789:user@example.com",
			ExpiresAt: numeric_date.New(now.Add(1 * time.Hour)),
			NotBefore: numeric_date.New(now),
			IssuedAt:  numeric_date.New(now),
			Issuer:    "test-issuer",
		},
		AuthenticationMethods: []string{"ext"},
	}

	tests := []struct {
		name    string
		token   *Token
		signer  interface{ Name() string; Sign([]byte) ([]byte, error) }
		wantErr bool
	}{
		{
			name: "successful encode",
			token: &Token{
				Claims:           claims,
				AuthenticationId: "auth-123",
				SessionId:        "session-456",
			},
			signer:  signer,
			wantErr: false,
		},
		{
			name: "nil signer",
			token: &Token{
				Claims:           claims,
				AuthenticationId: "auth-123",
			},
			signer:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tokenString string
			var err error

			if tt.signer == nil {
				tokenString, err = tt.token.Encode(nil)
			} else {
				tokenString, err = tt.token.Encode(tt.signer)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tokenString == "" {
				t.Error("Encode() returned empty string")
			}
		})
	}
}
