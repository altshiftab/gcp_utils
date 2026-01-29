package provider_claims

import (
	"errors"
	"testing"

	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
)

func TestGoogleClaims_VerifiedEmailAddress(t *testing.T) {
	tests := []struct {
		name          string
		claims        *GoogleClaims
		wantEmail     string
		wantErr       bool
		wantForbidden bool
	}{
		{
			name: "valid verified email",
			claims: &GoogleClaims{
				Email:         "test@example.com",
				EmailVerified: true,
				Sub:           "123456789",
				Hd:            "example.com",
			},
			wantEmail:     "test@example.com",
			wantErr:       false,
			wantForbidden: false,
		},
		{
			name: "empty email",
			claims: &GoogleClaims{
				Email:         "",
				EmailVerified: true,
				Sub:           "123456789",
			},
			wantEmail:     "",
			wantErr:       true,
			wantForbidden: true,
		},
		{
			name: "email not verified",
			claims: &GoogleClaims{
				Email:         "test@example.com",
				EmailVerified: false,
				Sub:           "123456789",
			},
			wantEmail:     "",
			wantErr:       true,
			wantForbidden: true,
		},
		{
			name: "empty email and not verified",
			claims: &GoogleClaims{
				Email:         "",
				EmailVerified: false,
				Sub:           "123456789",
			},
			wantEmail:     "",
			wantErr:       true,
			wantForbidden: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email, err := tt.claims.VerifiedEmailAddress()

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifiedEmailAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if email != tt.wantEmail {
				t.Errorf("VerifiedEmailAddress() email = %v, want %v", email, tt.wantEmail)
			}

			if tt.wantForbidden && err != nil {
				if !errors.Is(err, ssoErrors.ErrForbiddenUser) {
					t.Errorf("VerifiedEmailAddress() expected ErrForbiddenUser, got %v", err)
				}
			}
		})
	}
}

func TestMicrosoftClaims_VerifiedEmailAddress(t *testing.T) {
	tests := []struct {
		name          string
		claims        *MicrosoftClaims
		wantEmail     string
		wantErr       bool
		wantForbidden bool
	}{
		{
			name: "valid email",
			claims: &MicrosoftClaims{
				Email:             "test@example.com",
				PreferredUsername: "test",
				Upn:               "test@example.com",
				Sub:               "123456789",
				Tid:               "tenant-id",
			},
			wantEmail:     "test@example.com",
			wantErr:       false,
			wantForbidden: false,
		},
		{
			name: "empty email",
			claims: &MicrosoftClaims{
				Email:             "",
				PreferredUsername: "test",
				Upn:               "test@example.com",
				Sub:               "123456789",
				Tid:               "tenant-id",
			},
			wantEmail:     "",
			wantErr:       true,
			wantForbidden: true,
		},
		{
			name: "email with other fields empty",
			claims: &MicrosoftClaims{
				Email: "user@domain.com",
			},
			wantEmail:     "user@domain.com",
			wantErr:       false,
			wantForbidden: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email, err := tt.claims.VerifiedEmailAddress()

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifiedEmailAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if email != tt.wantEmail {
				t.Errorf("VerifiedEmailAddress() email = %v, want %v", email, tt.wantEmail)
			}

			if tt.wantForbidden && err != nil {
				if !errors.Is(err, ssoErrors.ErrForbiddenUser) {
					t.Errorf("VerifiedEmailAddress() expected ErrForbiddenUser, got %v", err)
				}
			}
		})
	}
}

func TestProviderClaimsInterface(t *testing.T) {
	// Verify that both types implement the ProviderClaims interface
	var _ ProviderClaims = &GoogleClaims{}
	var _ ProviderClaims = &MicrosoftClaims{}
}
