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

func TestAuthenticationContextMultiFactor(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                  string
		authenticationContext *AuthenticationContext
		expected              bool
	}{
		{name: "nil context", authenticationContext: nil},
		{name: "no method references", authenticationContext: &AuthenticationContext{}},
		{
			name:                  "single factor",
			authenticationContext: &AuthenticationContext{MethodReferences: []string{"pwd"}},
		},
		{
			name:                  "google style",
			authenticationContext: &AuthenticationContext{MethodReferences: []string{"mfa", "pwd", "tel"}},
			expected:              true,
		},
		{
			name:                  "microsoft multipleauthn",
			authenticationContext: &AuthenticationContext{MethodReferences: []string{"pwd", "multipleauthn"}},
			expected:              true,
		},
		{
			name:                  "case insensitive",
			authenticationContext: &AuthenticationContext{MethodReferences: []string{"MFA"}},
			expected:              true,
		},
		{
			// A hardware key alone is one factor as far as the provider's own statement goes.
			name:                  "hardware key without mfa",
			authenticationContext: &AuthenticationContext{MethodReferences: []string{"hwk"}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.authenticationContext.MultiFactor(); got != testCase.expected {
				t.Errorf("got %t, expected %t", got, testCase.expected)
			}
		})
	}
}

func TestProviderClaimsAuthenticationContext(t *testing.T) {
	t.Parallel()

	googleClaims := &GoogleClaims{Amr: []string{"mfa", "pwd"}, Acr: "google-acr", AuthTime: 1786868673}
	googleContext := googleClaims.AuthenticationContext()
	if googleContext == nil || !googleContext.MultiFactor() {
		t.Errorf("expected google claims to report multi factor")
	}
	if googleContext.ContextClass != "google-acr" || googleContext.AuthenticatedAt != 1786868673 {
		t.Errorf("google context: got %+v", googleContext)
	}

	microsoftClaims := &MicrosoftClaims{Amr: []string{"pwd"}, Acr: "1", AuthTime: 1786868673}
	microsoftContext := microsoftClaims.AuthenticationContext()
	if microsoftContext == nil || microsoftContext.MultiFactor() {
		t.Errorf("expected microsoft claims not to report multi factor")
	}
	if microsoftContext.ContextClass != "1" {
		t.Errorf("microsoft context: got %+v", microsoftContext)
	}
}
