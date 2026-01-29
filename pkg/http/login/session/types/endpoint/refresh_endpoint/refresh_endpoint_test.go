package refresh_endpoint

import (
	"testing"
	"time"

	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/refresh_endpoint/refresh_endpoint_config"
)

func TestNew(t *testing.T) {
	endpoint := New()

	if endpoint == nil {
		t.Fatal("New() returned nil")
	}

	// Verify default path from config
	defaultPath := refresh_endpoint_config.DefaultPath
	if endpoint.Path != defaultPath {
		t.Errorf("New() Path = %v, want %v", endpoint.Path, defaultPath)
	}

	// Verify method is POST
	if endpoint.Method != "POST" {
		t.Errorf("New() Method = %v, want POST", endpoint.Method)
	}
}

func TestNew_WithOptions(t *testing.T) {
	customPath := "/custom/refresh"
	customDuration := 2 * time.Hour

	endpoint := New(
		refresh_endpoint_config.WithPath(customPath),
		refresh_endpoint_config.WithSessionDuration(customDuration),
	)

	if endpoint == nil {
		t.Fatal("New() returned nil")
	}

	if endpoint.Path != customPath {
		t.Errorf("New() Path = %v, want %v", endpoint.Path, customPath)
	}

	if endpoint.SessionDuration != customDuration {
		t.Errorf("New() SessionDuration = %v, want %v", endpoint.SessionDuration, customDuration)
	}
}

func TestEndpoint_Initialize_NilAuthorizerRequestParser(t *testing.T) {
	endpoint := New()

	err := endpoint.Initialize(nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil authorizer request parser")
	}
}

func TestEndpoint_Initialize_NilSessionManager(t *testing.T) {
	endpoint := New()

	err := endpoint.Initialize(nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil session manager")
	}
}

func TestConstants(t *testing.T) {
	// Verify authentication method constants
	if RefreshAuthenticationMethod != "rtoken" {
		t.Errorf("RefreshAuthenticationMethod = %v, want rtoken", RefreshAuthenticationMethod)
	}

	if DbscAuthenticationMethod != "hwk" {
		t.Errorf("DbscAuthenticationMethod = %v, want hwk", DbscAuthenticationMethod)
	}

	if SsoAuthenticationMethod != "ext" {
		t.Errorf("SsoAuthenticationMethod = %v, want ext", SsoAuthenticationMethod)
	}
}

func TestEndpoint_SessionDuration(t *testing.T) {
	tests := []struct {
		name            string
		sessionDuration time.Duration
	}{
		{
			name:            "default duration",
			sessionDuration: refresh_endpoint_config.DefaultSessionDuration,
		},
		{
			name:            "1 hour",
			sessionDuration: 1 * time.Hour,
		},
		{
			name:            "30 minutes",
			sessionDuration: 30 * time.Minute,
		},
		{
			name:            "24 hours",
			sessionDuration: 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := New(refresh_endpoint_config.WithSessionDuration(tt.sessionDuration))

			if endpoint.SessionDuration != tt.sessionDuration {
				t.Errorf("SessionDuration = %v, want %v", endpoint.SessionDuration, tt.sessionDuration)
			}
		})
	}
}

func TestEndpoint_Path(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "default path",
			path: refresh_endpoint_config.DefaultPath,
		},
		{
			name: "custom path",
			path: "/api/v1/session/refresh",
		},
		{
			name: "root path",
			path: "/refresh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var endpoint *Endpoint
			if tt.path == refresh_endpoint_config.DefaultPath {
				endpoint = New()
			} else {
				endpoint = New(refresh_endpoint_config.WithPath(tt.path))
			}

			if endpoint.Path != tt.path {
				t.Errorf("Path = %v, want %v", endpoint.Path, tt.path)
			}
		})
	}
}

func TestEndpoint_Method(t *testing.T) {
	endpoint := New()

	// Refresh endpoint should always use POST method
	if endpoint.Method != "POST" {
		t.Errorf("Method = %v, want POST", endpoint.Method)
	}
}

func TestEndpoint_Initialized(t *testing.T) {
	endpoint := New()

	// Before initialization, Initialized should be false
	if endpoint.Initialized {
		t.Error("Initialized should be false before calling Initialize()")
	}
}
