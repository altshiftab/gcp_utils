package session

import (
	"encoding/base64"
	"testing"
)

func TestGenerateDbscChallenge(t *testing.T) {
	t.Run("generates valid base64 encoded challenge", func(t *testing.T) {
		challenge, err := GenerateDbscChallenge()
		if err != nil {
			t.Fatalf("GenerateDbscChallenge() unexpected error: %v", err)
		}

		if challenge == "" {
			t.Error("GenerateDbscChallenge() returned empty string")
		}

		// Verify it's valid base64
		decoded, err := base64.URLEncoding.DecodeString(challenge)
		if err != nil {
			t.Errorf("GenerateDbscChallenge() returned invalid base64: %v", err)
		}

		// Should be 64 bytes when decoded (as per implementation)
		if len(decoded) != 64 {
			t.Errorf("GenerateDbscChallenge() decoded length = %d, want 64", len(decoded))
		}
	})

	t.Run("generates unique challenges", func(t *testing.T) {
		challenges := make(map[string]bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			challenge, err := GenerateDbscChallenge()
			if err != nil {
				t.Fatalf("GenerateDbscChallenge() unexpected error on iteration %d: %v", i, err)
			}

			if challenges[challenge] {
				t.Errorf("GenerateDbscChallenge() generated duplicate challenge on iteration %d", i)
			}
			challenges[challenge] = true
		}

		if len(challenges) != iterations {
			t.Errorf("GenerateDbscChallenge() generated %d unique challenges, want %d", len(challenges), iterations)
		}
	})

	t.Run("challenge has sufficient entropy", func(t *testing.T) {
		challenge, err := GenerateDbscChallenge()
		if err != nil {
			t.Fatalf("GenerateDbscChallenge() unexpected error: %v", err)
		}

		// Base64 encoding of 64 bytes should be ~86 characters
		// (64 * 4 / 3 = 85.33, rounded up with padding)
		if len(challenge) < 80 {
			t.Errorf("GenerateDbscChallenge() challenge length = %d, want >= 80", len(challenge))
		}
	})
}
