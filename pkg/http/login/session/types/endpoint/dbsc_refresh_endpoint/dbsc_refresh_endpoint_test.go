package dbsc_refresh_endpoint

import (
	"testing"
	"time"

	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
)

func TestNew(t *testing.T) {
	endpoint := New()

	if endpoint == nil {
		t.Fatal("New() returned nil")
	}

	// Verify default path from config
	defaultPath := dbsc_refresh_endpoint_config.DefaultPath
	if endpoint.Path != defaultPath {
		t.Errorf("New() Path = %v, want %v", endpoint.Path, defaultPath)
	}

	// Verify method is POST
	if endpoint.Method != "POST" {
		t.Errorf("New() Method = %v, want POST", endpoint.Method)
	}

	// Verify default session duration
	defaultSessionDuration := dbsc_refresh_endpoint_config.DefaultSessionDuration
	if endpoint.SessionDuration != defaultSessionDuration {
		t.Errorf("New() SessionDuration = %v, want %v", endpoint.SessionDuration, defaultSessionDuration)
	}

	// Verify default challenge duration
	defaultChallengeDuration := dbsc_refresh_endpoint_config.DefaultChallengeDuration
	if endpoint.ChallengeDuration != defaultChallengeDuration {
		t.Errorf("New() ChallengeDuration = %v, want %v", endpoint.ChallengeDuration, defaultChallengeDuration)
	}
}

func TestNew_WithOptions(t *testing.T) {
	customPath := "/custom/dbsc/refresh"
	customSessionDuration := 2 * time.Hour
	customChallengeDuration := 10 * time.Minute

	endpoint := New(
		dbsc_refresh_endpoint_config.WithPath(customPath),
		dbsc_refresh_endpoint_config.WithSessionDuration(customSessionDuration),
		dbsc_refresh_endpoint_config.WithChallengeDuration(customChallengeDuration),
	)

	if endpoint == nil {
		t.Fatal("New() returned nil")
	}

	if endpoint.Path != customPath {
		t.Errorf("New() Path = %v, want %v", endpoint.Path, customPath)
	}

	if endpoint.SessionDuration != customSessionDuration {
		t.Errorf("New() SessionDuration = %v, want %v", endpoint.SessionDuration, customSessionDuration)
	}

	if endpoint.ChallengeDuration != customChallengeDuration {
		t.Errorf("New() ChallengeDuration = %v, want %v", endpoint.ChallengeDuration, customChallengeDuration)
	}
}

func TestEndpoint_Initialize_NilAuthorizerRequestParser(t *testing.T) {
	endpoint := New()

	err := endpoint.Initialize(nil, nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil authorizer request parser")
	}
}

func TestEndpoint_Initialize_NilDbscSessionResponseProcessor(t *testing.T) {
	endpoint := New()

	err := endpoint.Initialize(nil, nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil dbsc session response processor")
	}
}

func TestEndpoint_Initialize_NilSessionManager(t *testing.T) {
	endpoint := New()

	err := endpoint.Initialize(nil, nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil session manager")
	}
}

func TestConstants(t *testing.T) {
	// Verify DBSC authentication method constant
	if DbscAuthenticationMethod != "hwk" {
		t.Errorf("DbscAuthenticationMethod = %v, want hwk", DbscAuthenticationMethod)
	}

	// Verify session response header name constant
	expectedHeaderName := "Sec-Session-Response"
	if sessionResponseHeaderName != expectedHeaderName {
		t.Errorf("sessionResponseHeaderName = %v, want %v", sessionResponseHeaderName, expectedHeaderName)
	}
}

func TestEndpoint_SessionDuration(t *testing.T) {
	tests := []struct {
		name            string
		sessionDuration time.Duration
	}{
		{
			name:            "default duration",
			sessionDuration: dbsc_refresh_endpoint_config.DefaultSessionDuration,
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
			name:            "12 hours",
			sessionDuration: 12 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := New(dbsc_refresh_endpoint_config.WithSessionDuration(tt.sessionDuration))

			if endpoint.SessionDuration != tt.sessionDuration {
				t.Errorf("SessionDuration = %v, want %v", endpoint.SessionDuration, tt.sessionDuration)
			}
		})
	}
}

func TestEndpoint_ChallengeDuration(t *testing.T) {
	tests := []struct {
		name              string
		challengeDuration time.Duration
	}{
		{
			name:              "default duration",
			challengeDuration: dbsc_refresh_endpoint_config.DefaultChallengeDuration,
		},
		{
			name:              "5 minutes",
			challengeDuration: 5 * time.Minute,
		},
		{
			name:              "10 minutes",
			challengeDuration: 10 * time.Minute,
		},
		{
			name:              "1 minute",
			challengeDuration: 1 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := New(dbsc_refresh_endpoint_config.WithChallengeDuration(tt.challengeDuration))

			if endpoint.ChallengeDuration != tt.challengeDuration {
				t.Errorf("ChallengeDuration = %v, want %v", endpoint.ChallengeDuration, tt.challengeDuration)
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
			path: dbsc_refresh_endpoint_config.DefaultPath,
		},
		{
			name: "custom path",
			path: "/api/v1/dbsc/refresh",
		},
		{
			name: "nested path",
			path: "/auth/session/dbsc/refresh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var endpoint *Endpoint
			if tt.path == dbsc_refresh_endpoint_config.DefaultPath {
				endpoint = New()
			} else {
				endpoint = New(dbsc_refresh_endpoint_config.WithPath(tt.path))
			}

			if endpoint.Path != tt.path {
				t.Errorf("Path = %v, want %v", endpoint.Path, tt.path)
			}
		})
	}
}

func TestEndpoint_Method(t *testing.T) {
	endpoint := New()

	// DBSC refresh endpoint should always use POST method
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

func TestEndpoint_Endpoint(t *testing.T) {
	endpoint := New()

	if endpoint.Endpoint == nil {
		t.Error("Endpoint.Endpoint is nil")
		return
	}

	if endpoint.Endpoint.Endpoint == nil {
		t.Error("Endpoint.Endpoint.Endpoint is nil")
	}
}
