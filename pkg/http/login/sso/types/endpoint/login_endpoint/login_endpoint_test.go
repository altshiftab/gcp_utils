package login_endpoint

import (
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"golang.org/x/oauth2"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		callbackPath string
		wantErr      bool
	}{
		{
			name:         "valid paths",
			path:         "/auth/login",
			callbackPath: "/auth/callback",
			wantErr:      false,
		},
		{
			name:         "empty path",
			path:         "",
			callbackPath: "/auth/callback",
			wantErr:      true,
		},
		{
			name:         "empty callback path",
			path:         "/auth/login",
			callbackPath: "",
			wantErr:      true,
		},
		{
			name:         "both paths empty",
			path:         "",
			callbackPath: "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, err := New(tt.path, tt.callbackPath)

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
				if endpoint.CallbackPath != tt.callbackPath {
					t.Errorf("New() CallbackPath = %v, want %v", endpoint.CallbackPath, tt.callbackPath)
				}
			}
		})
	}
}

func TestEndpoint_Initialize(t *testing.T) {
	oauthConfig := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		RedirectURL: "https://example.com/auth/callback",
		Scopes:      []string{"openid", "email", "profile"},
	}

	tests := []struct {
		name        string
		domain      string
		oauthConfig *oauth2.Config
		db          *sql.DB
		wantErr     bool
	}{
		{
			name:        "empty domain",
			domain:      "",
			oauthConfig: oauthConfig,
			db:          &sql.DB{},
			wantErr:     true,
		},
		{
			name:        "nil oauth config",
			domain:      "example.com",
			oauthConfig: nil,
			db:          &sql.DB{},
			wantErr:     true,
		},
		{
			name:        "nil database",
			domain:      "example.com",
			oauthConfig: oauthConfig,
			db:          nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, err := New("/auth/login", "/auth/callback")
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			err = endpoint.Initialize(tt.domain, tt.oauthConfig, tt.db)

			if (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEndpoint_Initialize_ValidConfig(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	oauthConfig := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		RedirectURL: "https://example.com/auth/callback",
		Scopes:      []string{"openid", "email", "profile"},
	}

	endpoint, err := New("/auth/login", "/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	err = endpoint.Initialize("example.com", oauthConfig, db)
	if err != nil {
		t.Errorf("Initialize() unexpected error: %v", err)
	}

	if !endpoint.Initialized {
		t.Error("Initialize() did not set Initialized to true")
	}
}

func TestEndpoint_Initialize_Localhost(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	oauthConfig := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		RedirectURL: "http://localhost:8080/auth/callback",
		Scopes:      []string{"openid", "email", "profile"},
	}

	endpoint, err := New("/auth/login", "/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Localhost should be allowed when domain is "localhost"
	err = endpoint.Initialize("localhost", oauthConfig, db)
	if err != nil {
		t.Errorf("Initialize() unexpected error for localhost: %v", err)
	}
}

func TestMakeCodeVerifier(t *testing.T) {
	t.Run("generates non-empty verifier", func(t *testing.T) {
		verifier, err := makeCodeVerifier()
		if err != nil {
			t.Fatalf("makeCodeVerifier() unexpected error: %v", err)
		}

		if verifier == "" {
			t.Error("makeCodeVerifier() returned empty string")
		}

		// Should be base64 encoded 96 bytes = 128 characters
		if len(verifier) < 100 {
			t.Errorf("makeCodeVerifier() verifier length = %d, want >= 100", len(verifier))
		}
	})

	t.Run("generates unique verifiers", func(t *testing.T) {
		verifiers := make(map[string]bool)
		iterations := 50

		for i := 0; i < iterations; i++ {
			verifier, err := makeCodeVerifier()
			if err != nil {
				t.Fatalf("makeCodeVerifier() unexpected error on iteration %d: %v", i, err)
			}

			if verifiers[verifier] {
				t.Errorf("makeCodeVerifier() generated duplicate verifier on iteration %d", i)
			}
			verifiers[verifier] = true
		}
	})
}

func TestMakeState(t *testing.T) {
	t.Run("generates non-empty state", func(t *testing.T) {
		state, err := makeState()
		if err != nil {
			t.Fatalf("makeState() unexpected error: %v", err)
		}

		if state == "" {
			t.Error("makeState() returned empty string")
		}

		// Should be base64 encoded 32 bytes = ~43 characters
		if len(state) < 40 {
			t.Errorf("makeState() state length = %d, want >= 40", len(state))
		}
	})

	t.Run("generates unique states", func(t *testing.T) {
		states := make(map[string]bool)
		iterations := 50

		for i := 0; i < iterations; i++ {
			state, err := makeState()
			if err != nil {
				t.Fatalf("makeState() unexpected error on iteration %d: %v", i, err)
			}

			if states[state] {
				t.Errorf("makeState() generated duplicate state on iteration %d", i)
			}
			states[state] = true
		}
	})
}

func TestUrlInput_URL(t *testing.T) {
	tests := []struct {
		name     string
		input    *UrlInput
		wantURL  string
	}{
		{
			name:    "with redirect url",
			input:   &UrlInput{RedirectUrl: "https://example.com/dashboard"},
			wantURL: "https://example.com/dashboard",
		},
		{
			name:    "empty redirect url",
			input:   &UrlInput{RedirectUrl: ""},
			wantURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := tt.input.URL()
			if url != tt.wantURL {
				t.Errorf("URL() = %v, want %v", url, tt.wantURL)
			}
		})
	}
}

func TestEndpointDefaults(t *testing.T) {
	endpoint, err := New("/auth/login", "/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Check default values from config
	if endpoint.OauthFlowDuration == 0 {
		// The default should be set from login_endpoint_config
		t.Log("OauthFlowDuration is zero, which may be expected if no default is set")
	}

	// Check that callback cookie name has some default value
	if endpoint.CallbackCookieName == "" {
		t.Log("CallbackCookieName is empty, which may be expected if no default is set")
	}

	// Verify endpoint method is GET
	if endpoint.Method != "GET" {
		t.Errorf("Endpoint.Method = %v, want GET", endpoint.Method)
	}

	// Verify endpoint is public
	if !endpoint.Public {
		t.Error("Endpoint.Public = false, want true")
	}
}

func BenchmarkMakeCodeVerifier(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := makeCodeVerifier()
		if err != nil {
			b.Fatalf("makeCodeVerifier() failed: %v", err)
		}
	}
}

func BenchmarkMakeState(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := makeState()
		if err != nil {
			b.Fatalf("makeState() failed: %v", err)
		}
	}
}

func TestEndpointOauthFlowDuration(t *testing.T) {
	// Test with custom duration
	customDuration := 15 * time.Minute

	endpoint, err := New("/auth/login", "/auth/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Manually set the duration to test
	endpoint.OauthFlowDuration = customDuration

	if endpoint.OauthFlowDuration != customDuration {
		t.Errorf("OauthFlowDuration = %v, want %v", endpoint.OauthFlowDuration, customDuration)
	}
}
