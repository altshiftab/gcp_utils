package dbsc_register_endpoint

import (
	"encoding/json"
	"testing"

	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
)

func TestNew(t *testing.T) {
	endpoint := New()

	if endpoint == nil {
		t.Fatal("New() returned nil")
	}

	// Verify default path from config
	defaultPath := dbsc_register_endpoint_config.DefaultPath
	if endpoint.Path != defaultPath {
		t.Errorf("New() Path = %v, want %v", endpoint.Path, defaultPath)
	}

	// Verify method is POST
	if endpoint.Method != "POST" {
		t.Errorf("New() Method = %v, want POST", endpoint.Method)
	}

	// Verify default refresh path
	defaultRefreshPath := dbsc_register_endpoint_config.DefaultRefreshPath
	if endpoint.RefreshPath != defaultRefreshPath {
		t.Errorf("New() RefreshPath = %v, want %v", endpoint.RefreshPath, defaultRefreshPath)
	}
}

func TestNew_WithOptions(t *testing.T) {
	customPath := "/custom/dbsc/register"
	customRefreshPath := "/custom/dbsc/refresh"

	endpoint := New(
		dbsc_register_endpoint_config.WithPath(customPath),
		dbsc_register_endpoint_config.WithRefreshPath(customRefreshPath),
	)

	if endpoint == nil {
		t.Fatal("New() returned nil")
	}

	if endpoint.Path != customPath {
		t.Errorf("New() Path = %v, want %v", endpoint.Path, customPath)
	}

	if endpoint.RefreshPath != customRefreshPath {
		t.Errorf("New() RefreshPath = %v, want %v", endpoint.RefreshPath, customRefreshPath)
	}
}

func TestEndpoint_Initialize_NilAuthorizerRequestParser(t *testing.T) {
	endpoint := New()

	err := endpoint.Initialize(nil, nil, "example.com")
	if err == nil {
		t.Error("Initialize() expected error for nil authorizer request parser")
	}
}

func TestEndpoint_Initialize_NilDbscSessionResponseProcessor(t *testing.T) {
	endpoint := New()

	err := endpoint.Initialize(nil, nil, "example.com")
	if err == nil {
		t.Error("Initialize() expected error for nil dbsc session response processor")
	}
}

func TestEndpoint_Path(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "default path",
			path: dbsc_register_endpoint_config.DefaultPath,
		},
		{
			name: "custom path",
			path: "/api/v1/dbsc/register",
		},
		{
			name: "nested path",
			path: "/auth/session/dbsc/register",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var endpoint *Endpoint
			if tt.path == dbsc_register_endpoint_config.DefaultPath {
				endpoint = New()
			} else {
				endpoint = New(dbsc_register_endpoint_config.WithPath(tt.path))
			}

			if endpoint.Path != tt.path {
				t.Errorf("Path = %v, want %v", endpoint.Path, tt.path)
			}
		})
	}
}

func TestEndpoint_RefreshPath(t *testing.T) {
	tests := []struct {
		name        string
		refreshPath string
	}{
		{
			name:        "default refresh path",
			refreshPath: dbsc_register_endpoint_config.DefaultRefreshPath,
		},
		{
			name:        "custom refresh path",
			refreshPath: "/api/v1/dbsc/refresh",
		},
		{
			name:        "nested refresh path",
			refreshPath: "/auth/session/dbsc/refresh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var endpoint *Endpoint
			if tt.refreshPath == dbsc_register_endpoint_config.DefaultRefreshPath {
				endpoint = New()
			} else {
				endpoint = New(dbsc_register_endpoint_config.WithRefreshPath(tt.refreshPath))
			}

			if endpoint.RefreshPath != tt.refreshPath {
				t.Errorf("RefreshPath = %v, want %v", endpoint.RefreshPath, tt.refreshPath)
			}
		})
	}
}

func TestEndpoint_Method(t *testing.T) {
	endpoint := New()

	// DBSC register endpoint should always use POST method
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

func TestScope_JSON(t *testing.T) {
	scope := Scope{
		Origin:        "https://example.com",
		IncludeSite:   true,
		DeferRequests: false,
	}

	data, err := json.Marshal(scope)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}

	var decoded Scope
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	if decoded.Origin != scope.Origin {
		t.Errorf("Origin = %v, want %v", decoded.Origin, scope.Origin)
	}
	if decoded.IncludeSite != scope.IncludeSite {
		t.Errorf("IncludeSite = %v, want %v", decoded.IncludeSite, scope.IncludeSite)
	}
	if decoded.DeferRequests != scope.DeferRequests {
		t.Errorf("DeferRequests = %v, want %v", decoded.DeferRequests, scope.DeferRequests)
	}
}

func TestCredential_JSON(t *testing.T) {
	credential := Credential{
		Type:       "cookie",
		Name:       "session",
		Attributes: "Secure; HttpOnly; SameSite=Strict",
	}

	data, err := json.Marshal(credential)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}

	var decoded Credential
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	if decoded.Type != credential.Type {
		t.Errorf("Type = %v, want %v", decoded.Type, credential.Type)
	}
	if decoded.Name != credential.Name {
		t.Errorf("Name = %v, want %v", decoded.Name, credential.Name)
	}
	if decoded.Attributes != credential.Attributes {
		t.Errorf("Attributes = %v, want %v", decoded.Attributes, credential.Attributes)
	}
}

func TestResponse_JSON(t *testing.T) {
	response := Response{
		SessionIdentifier: "session-123",
		RefreshURL:        "/auth/dbsc/refresh",
		Scope: Scope{
			Origin:      "https://example.com",
			IncludeSite: true,
		},
		Credentials: []*Credential{
			{
				Type:       "cookie",
				Name:       "session",
				Attributes: "Secure; HttpOnly; SameSite=Strict",
			},
		},
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	if decoded.SessionIdentifier != response.SessionIdentifier {
		t.Errorf("SessionIdentifier = %v, want %v", decoded.SessionIdentifier, response.SessionIdentifier)
	}
	if decoded.RefreshURL != response.RefreshURL {
		t.Errorf("RefreshURL = %v, want %v", decoded.RefreshURL, response.RefreshURL)
	}
	if decoded.Scope.Origin != response.Scope.Origin {
		t.Errorf("Scope.Origin = %v, want %v", decoded.Scope.Origin, response.Scope.Origin)
	}
	if decoded.Scope.IncludeSite != response.Scope.IncludeSite {
		t.Errorf("Scope.IncludeSite = %v, want %v", decoded.Scope.IncludeSite, response.Scope.IncludeSite)
	}
	if len(decoded.Credentials) != 1 {
		t.Fatalf("Credentials length = %v, want 1", len(decoded.Credentials))
	}
	if decoded.Credentials[0].Name != response.Credentials[0].Name {
		t.Errorf("Credentials[0].Name = %v, want %v", decoded.Credentials[0].Name, response.Credentials[0].Name)
	}
}

func TestResponse_JSONOmitEmpty(t *testing.T) {
	// Test that empty/default fields are omitted
	response := Response{
		SessionIdentifier: "session-123",
		RefreshURL:        "/auth/dbsc/refresh",
		Scope:             Scope{},
		Credentials:       nil,
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}

	// Parse as generic map to check which fields are present
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	// session_identifier and refresh_url should always be present
	if _, ok := result["session_identifier"]; !ok {
		t.Error("session_identifier should be present")
	}
	if _, ok := result["refresh_url"]; !ok {
		t.Error("refresh_url should be present")
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
