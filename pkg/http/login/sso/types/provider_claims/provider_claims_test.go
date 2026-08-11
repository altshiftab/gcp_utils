package provider_claims

import (
	"errors"
	"testing"

	ssoErrors "github.com/altshiftab/gcp_utils/pkg/http/login/sso/errors"
)

func TestGoogleClaimsVerifiedEmailAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		claims      *GoogleClaims
		expected    string
		expectError bool
	}{
		{
			name:     "verified",
			claims:   &GoogleClaims{Email: "test@example.com", EmailVerified: true},
			expected: "test@example.com",
		},
		{
			name:        "empty email",
			claims:      &GoogleClaims{EmailVerified: true},
			expectError: true,
		},
		{
			name:        "unverified email",
			claims:      &GoogleClaims{Email: "test@example.com"},
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			emailAddress, err := testCase.claims.VerifiedEmailAddress()
			if testCase.expectError {
				if !errors.Is(err, ssoErrors.ErrForbiddenUser) {
					t.Fatalf("expected forbidden user error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("verified email address: %v", err)
			}

			if emailAddress != testCase.expected {
				t.Errorf("email address: got %q, want %q", emailAddress, testCase.expected)
			}
		})
	}
}

func TestMicrosoftClaimsVerifiedEmailAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		claims      *MicrosoftClaims
		expected    string
		expectError bool
	}{
		{
			name:     "email present",
			claims:   &MicrosoftClaims{Email: "test@example.com"},
			expected: "test@example.com",
		},
		{
			name:        "empty email",
			claims:      &MicrosoftClaims{PreferredUsername: "test@example.com"},
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			emailAddress, err := testCase.claims.VerifiedEmailAddress()
			if testCase.expectError {
				if !errors.Is(err, ssoErrors.ErrForbiddenUser) {
					t.Fatalf("expected forbidden user error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("verified email address: %v", err)
			}

			if emailAddress != testCase.expected {
				t.Errorf("email address: got %q, want %q", emailAddress, testCase.expected)
			}
		})
	}
}
