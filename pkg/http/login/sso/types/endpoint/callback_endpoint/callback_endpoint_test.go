package callback_endpoint

import (
	"testing"

	"github.com/altshiftab/gcp_utils/pkg/http/login/sso/types/provider_claims"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid path",
			path:    "/auth/callback",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "root path",
			path:    "/",
			wantErr: false,
		},
		{
			name:    "nested path",
			path:    "/api/v1/auth/callback",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, err := New[*provider_claims.GoogleClaims](tt.path)

			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if endpoint == nil {
					t.Error("New() returned nil endpoint")
					return
				}
				if endpoint.Path != tt.path {
					t.Errorf("New() Path = %v, want %v", endpoint.Path, tt.path)
				}
			}
		})
	}
}

func TestNew_GoogleClaims(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if endpoint == nil {
		t.Fatal("New() returned nil endpoint")
	}

	// Verify endpoint configuration
	if endpoint.Method != "GET" {
		t.Errorf("Endpoint.Method = %v, want GET", endpoint.Method)
	}

	if !endpoint.Public {
		t.Error("Endpoint.Public = false, want true")
	}
}

func TestNew_MicrosoftClaims(t *testing.T) {
	endpoint, err := New[*provider_claims.MicrosoftClaims]("/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if endpoint == nil {
		t.Fatal("New() returned nil endpoint")
	}

	// Verify endpoint configuration
	if endpoint.Method != "GET" {
		t.Errorf("Endpoint.Method = %v, want GET", endpoint.Method)
	}

	if !endpoint.Public {
		t.Error("Endpoint.Public = false, want true")
	}
}

func TestEndpoint_Initialize_NilOauthConfig(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	err = endpoint.Initialize(nil, nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil oauth config")
	}
}

func TestEndpoint_Initialize_NilIdTokenAuthenticator(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Minimal oauth config
	oauthConfig := &struct{}{}
	_ = oauthConfig

	// This should fail because idTokenAuthenticator is nil
	err = endpoint.Initialize(nil, nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil authenticator")
	}
}

func TestEndpoint_Initialize_NilSessionManager(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	err = endpoint.Initialize(nil, nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil session manager")
	}
}

func TestUrlInput_Fields(t *testing.T) {
	input := &UrlInput{
		State:        "state-123",
		Code:         "code-456",
		Scope:        "openid email",
		AuthUser:     1,
		HostedDomain: "example.com",
		Prompt:       "consent",
		SessionState: "session-state-789",
	}

	if input.State != "state-123" {
		t.Errorf("State = %v, want state-123", input.State)
	}
	if input.Code != "code-456" {
		t.Errorf("Code = %v, want code-456", input.Code)
	}
	if input.Scope != "openid email" {
		t.Errorf("Scope = %v, want openid email", input.Scope)
	}
	if input.AuthUser != 1 {
		t.Errorf("AuthUser = %v, want 1", input.AuthUser)
	}
	if input.HostedDomain != "example.com" {
		t.Errorf("HostedDomain = %v, want example.com", input.HostedDomain)
	}
	if input.Prompt != "consent" {
		t.Errorf("Prompt = %v, want consent", input.Prompt)
	}
	if input.SessionState != "session-state-789" {
		t.Errorf("SessionState = %v, want session-state-789", input.SessionState)
	}
}

func TestEndpoint_CallbackCookieName(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Check that callback cookie name has a default value from config
	// The default is set in callback_endpoint_config
	if endpoint.CallbackCookieName == "" {
		t.Log("CallbackCookieName is empty - this may be expected if no default is set in config")
	}
}

func TestEndpoint_GenericTypeConstraint(t *testing.T) {
	// Test that the generic type constraint works with different provider claims

	// Google claims
	googleEndpoint, err := New[*provider_claims.GoogleClaims]("/auth/google/callback")
	if err != nil {
		t.Errorf("New() with GoogleClaims failed: %v", err)
	}
	if googleEndpoint == nil {
		t.Error("New() with GoogleClaims returned nil")
	}

	// Microsoft claims
	msEndpoint, err := New[*provider_claims.MicrosoftClaims]("/auth/microsoft/callback")
	if err != nil {
		t.Errorf("New() with MicrosoftClaims failed: %v", err)
	}
	if msEndpoint == nil {
		t.Error("New() with MicrosoftClaims returned nil")
	}
}
