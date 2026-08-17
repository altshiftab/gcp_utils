package main

import (
	"strings"
	"testing"
)

func TestExtensionIdFromKey(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		keyBase64   string
		expected    string
		expectError bool
	}{
		{
			name:      "known answer",
			keyBase64: "dGVzdC1rZXktbWF0ZXJpYWw=",
			expected:  "ljlceignlljbhgajnlfehjhgkbhnpgfk",
		},
		{
			name:        "invalid base64",
			keyBase64:   "not base64!",
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			extensionId, err := extensionIdFromKey(testCase.keyBase64)
			if testCase.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("extension id from key: %v", err)
			}

			if extensionId != testCase.expected {
				t.Errorf("extension id: got %q, want %q", extensionId, testCase.expected)
			}

			if len(extensionId) != 32 || strings.Trim(extensionId, map16) != "" {
				t.Errorf("extension id not 32 characters of %q: %q", map16, extensionId)
			}
		})
	}
}
