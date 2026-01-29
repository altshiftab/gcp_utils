package id_token_endpoint

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
			path:    "/auth/token",
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
			path:    "/api/v1/auth/id-token",
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
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/token")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if endpoint == nil {
		t.Fatal("New() returned nil endpoint")
	}

	// Verify endpoint configuration
	if endpoint.Method != "POST" {
		t.Errorf("Endpoint.Method = %v, want POST", endpoint.Method)
	}

	if !endpoint.Public {
		t.Error("Endpoint.Public = false, want true")
	}

	// Verify body loader configuration
	if endpoint.BodyLoader == nil {
		t.Error("Endpoint.BodyLoader is nil")
	} else {
		if endpoint.BodyLoader.ContentType != "application/jose" {
			t.Errorf("Endpoint.BodyLoader.ContentType = %v, want application/jose", endpoint.BodyLoader.ContentType)
		}
		if endpoint.BodyLoader.MaxBytes != 4096 {
			t.Errorf("Endpoint.BodyLoader.MaxBytes = %v, want 4096", endpoint.BodyLoader.MaxBytes)
		}
	}
}

func TestNew_MicrosoftClaims(t *testing.T) {
	endpoint, err := New[*provider_claims.MicrosoftClaims]("/auth/token")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if endpoint == nil {
		t.Fatal("New() returned nil endpoint")
	}

	// Verify endpoint configuration
	if endpoint.Method != "POST" {
		t.Errorf("Endpoint.Method = %v, want POST", endpoint.Method)
	}

	if !endpoint.Public {
		t.Error("Endpoint.Public = false, want true")
	}
}

func TestEndpoint_Initialize_NilCseBodyParser(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/token")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	err = endpoint.Initialize(nil, nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil cse body parser")
	}
}

func TestEndpoint_Initialize_NilBodyLoader(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/token")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Set body loader to nil to test validation
	endpoint.BodyLoader = nil

	err = endpoint.Initialize(nil, nil, nil)
	if err == nil {
		t.Error("Initialize() expected error for nil body loader")
	}
}

func TestBodyInput_Fields(t *testing.T) {
	input := &BodyInput{
		Token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIn0.sig",
	}

	if input.Token == "" {
		t.Error("Token should not be empty")
	}

	// Test empty token
	emptyInput := &BodyInput{Token: ""}
	if emptyInput.Token != "" {
		t.Error("Empty token should be empty string")
	}
}

func TestEndpoint_GenericTypeConstraint(t *testing.T) {
	// Test that the generic type constraint works with different provider claims

	// Google claims
	googleEndpoint, err := New[*provider_claims.GoogleClaims]("/auth/google/token")
	if err != nil {
		t.Errorf("New() with GoogleClaims failed: %v", err)
	}
	if googleEndpoint == nil {
		t.Error("New() with GoogleClaims returned nil")
	}

	// Microsoft claims
	msEndpoint, err := New[*provider_claims.MicrosoftClaims]("/auth/microsoft/token")
	if err != nil {
		t.Errorf("New() with MicrosoftClaims failed: %v", err)
	}
	if msEndpoint == nil {
		t.Error("New() with MicrosoftClaims returned nil")
	}
}

func TestEndpoint_Hint(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/token")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if endpoint.Hint == nil {
		t.Error("Endpoint.Hint is nil")
		return
	}

	if endpoint.Hint.InputType == nil {
		t.Error("Endpoint.Hint.InputType is nil")
	}
}

func TestEndpoint_ContentType(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/token")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if endpoint.BodyLoader == nil {
		t.Fatal("BodyLoader is nil")
	}

	// The endpoint expects JOSE (JSON Object Signing and Encryption) content type
	// for client-side encrypted payloads
	expectedContentType := "application/jose"
	if endpoint.BodyLoader.ContentType != expectedContentType {
		t.Errorf("ContentType = %v, want %v", endpoint.BodyLoader.ContentType, expectedContentType)
	}
}

func TestEndpoint_MaxBytes(t *testing.T) {
	endpoint, err := New[*provider_claims.GoogleClaims]("/auth/token")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if endpoint.BodyLoader == nil {
		t.Fatal("BodyLoader is nil")
	}

	// Max bytes should be 4096 for ID token payloads
	expectedMaxBytes := int64(4096)
	if endpoint.BodyLoader.MaxBytes != expectedMaxBytes {
		t.Errorf("MaxBytes = %v, want %v", endpoint.BodyLoader.MaxBytes, expectedMaxBytes)
	}
}
