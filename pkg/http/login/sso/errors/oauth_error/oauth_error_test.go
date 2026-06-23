package oauth_error

import (
	"testing"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
)

// Error must satisfy the error context extractor's CodeErrorI so that the OAuth
// error code is emitted as ECS `error.code`.
var _ motmedelErrors.CodeErrorI = (*Error)(nil)

func TestError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		code        string
		subcode     string
		description string
		uri         string
		want        string
	}{
		{
			name: "code only",
			code: "access_denied",
			want: "oauth error: access_denied",
		},
		{
			name:    "code and subcode",
			code:    "access_denied",
			subcode: "cancel",
			want:    "oauth error: access_denied (cancel)",
		},
		{
			name:        "code and description",
			code:        "access_denied",
			description: "User declined to consent to access the app.",
			want:        "oauth error: access_denied: User declined to consent to access the app.",
		},
		{
			name:        "all fields",
			code:        "access_denied",
			subcode:     "cancel",
			description: "User declined to consent to access the app.",
			uri:         "https://example.com/error",
			want:        "oauth error: access_denied (cancel): User declined to consent to access the app.",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := New(testCase.code, testCase.subcode, testCase.description, testCase.uri)
			if got := err.Error(); got != testCase.want {
				t.Errorf("Error() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestGetCode(t *testing.T) {
	t.Parallel()

	err := New("access_denied", "cancel", "User declined.", "https://example.com/error")
	if got := err.GetCode(); got != "access_denied" {
		t.Errorf("GetCode() = %q, want %q", got, "access_denied")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	err := New("access_denied", "cancel", "User declined.", "https://example.com/error")
	if err.Code != "access_denied" {
		t.Errorf("Code = %q, want %q", err.Code, "access_denied")
	}
	if err.Subcode != "cancel" {
		t.Errorf("Subcode = %q, want %q", err.Subcode, "cancel")
	}
	if err.Description != "User declined." {
		t.Errorf("Description = %q, want %q", err.Description, "User declined.")
	}
	if err.Uri != "https://example.com/error" {
		t.Errorf("Uri = %q, want %q", err.Uri, "https://example.com/error")
	}
}
