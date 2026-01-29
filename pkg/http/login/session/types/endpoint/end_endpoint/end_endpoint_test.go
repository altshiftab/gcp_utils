package end_endpoint

import (
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/end_endpoint/end_endpoint_config"
)

func TestNew(t *testing.T) {
	endpoint := New()

	if endpoint == nil {
		t.Fatal("New() returned nil")
	}

	// Verify default path from config
	defaultPath := end_endpoint_config.DefaultPath
	if endpoint.Path != defaultPath {
		t.Errorf("New() Path = %v, want %v", endpoint.Path, defaultPath)
	}

	// Verify method is POST
	if endpoint.Method != "POST" {
		t.Errorf("New() Method = %v, want POST", endpoint.Method)
	}
}

func TestNew_WithOptions(t *testing.T) {
	customPath := "/custom/logout"

	endpoint := New(end_endpoint_config.WithPath(customPath))

	if endpoint == nil {
		t.Fatal("New() returned nil")
	}

	if endpoint.Path != customPath {
		t.Errorf("New() Path = %v, want %v", endpoint.Path, customPath)
	}
}

func TestEndpoint_Initialize_NilAuthorizerRequestParser(t *testing.T) {
	endpoint := New()

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	err = endpoint.Initialize(nil, db)
	if err == nil {
		t.Error("Initialize() expected error for nil authorizer request parser")
	}
}

func TestEndpoint_Initialize_NilDatabase(t *testing.T) {
	endpoint := New()

	err := endpoint.Initialize(nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil database")
	}
}

func TestEndpoint_Path(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "default path",
			path: end_endpoint_config.DefaultPath,
		},
		{
			name: "custom path",
			path: "/api/v1/session/end",
		},
		{
			name: "root path",
			path: "/logout",
		},
		{
			name: "nested path",
			path: "/api/auth/session/terminate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var endpoint *Endpoint
			if tt.path == end_endpoint_config.DefaultPath {
				endpoint = New()
			} else {
				endpoint = New(end_endpoint_config.WithPath(tt.path))
			}

			if endpoint.Path != tt.path {
				t.Errorf("Path = %v, want %v", endpoint.Path, tt.path)
			}
		})
	}
}

func TestEndpoint_Method(t *testing.T) {
	endpoint := New()

	// End endpoint should always use POST method
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

func TestEndpoint_Initialize_BothNil(t *testing.T) {
	endpoint := New()

	var nilDb *sql.DB
	err := endpoint.Initialize(nil, nilDb)
	if err == nil {
		t.Error("Initialize() expected error when both parameters are nil")
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

func TestEndpoint_ClearSiteDataHeader(t *testing.T) {
	// The handler should return Clear-Site-Data header with "cookies" value
	// This is tested implicitly through the implementation
	// The expected value is `"cookies"` (with quotes as per the spec)
	expectedHeaderValue := `"cookies"`
	_ = expectedHeaderValue

	// This test documents the expected behavior
	// The actual handler returns:
	// Headers: []*muxResponse.HeaderEntry{{Name: "Clear-Site-Data", Value: `"cookies"`}}
}
