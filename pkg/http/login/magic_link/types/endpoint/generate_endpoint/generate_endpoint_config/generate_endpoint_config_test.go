package generate_endpoint_config

import (
	"net/mail"
	"net/url"
	"testing"
	"time"

	"github.com/Motmedel/utils_go/pkg/mail/types/message"
)

func TestNew_Defaults(t *testing.T) {
	t.Parallel()

	c := New()

	if c.Path != DefaultPath {
		t.Errorf("Path: got %q, want %q", c.Path, DefaultPath)
	}
	if c.LinkExpiration != DefaultLinkExpiration {
		t.Errorf("LinkExpiration: got %v, want %v", c.LinkExpiration, DefaultLinkExpiration)
	}
	if c.Subject != DefaultSubject {
		t.Errorf("Subject: got %q, want %q", c.Subject, DefaultSubject)
	}
	if c.MaxBytes != DefaultMaxBytes {
		t.Errorf("MaxBytes: got %d, want %d", c.MaxBytes, DefaultMaxBytes)
	}
	if c.MessageBuilder == nil {
		t.Errorf("MessageBuilder is nil")
	}
	if c.MakeNonce == nil {
		t.Errorf("MakeNonce is nil")
	}
}

func TestNew_Options(t *testing.T) {
	t.Parallel()

	customBuilder := func(_ *mail.Address, _ *url.URL, _ time.Time) (*message.Body, error) {
		return &message.Body{Content: []byte("custom"), ContentType: "text/plain"}, nil
	}
	customNonce := func() string { return "fixed-nonce" }

	c := New(
		WithPath("/custom"),
		WithLinkExpiration(5*time.Minute),
		WithSubject("Hi"),
		WithMaxBytes(2048),
		WithMessageBuilder(customBuilder),
		WithMakeNonce(customNonce),
	)

	if c.Path != "/custom" {
		t.Errorf("Path: got %q", c.Path)
	}
	if c.LinkExpiration != 5*time.Minute {
		t.Errorf("LinkExpiration: got %v", c.LinkExpiration)
	}
	if c.Subject != "Hi" {
		t.Errorf("Subject: got %q", c.Subject)
	}
	if c.MaxBytes != 2048 {
		t.Errorf("MaxBytes: got %d", c.MaxBytes)
	}
	if got := c.MakeNonce(); got != "fixed-nonce" {
		t.Errorf("MakeNonce(): got %q", got)
	}
	body, err := c.MessageBuilder(&mail.Address{Address: "a@b.c"}, &url.URL{}, time.Now())
	if err != nil {
		t.Fatalf("MessageBuilder: %v", err)
	}
	if string(body.Content) != "custom" {
		t.Errorf("MessageBuilder content: got %q", body.Content)
	}
}

func TestDefaultMessageBuilder(t *testing.T) {
	t.Parallel()

	linkUrl, _ := url.Parse("https://example.com/magic?token=abc")
	expires := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	body, err := DefaultMessageBuilder(&mail.Address{Address: "x@y.z"}, linkUrl, expires)
	if err != nil {
		t.Fatalf("DefaultMessageBuilder: %v", err)
	}
	if body == nil {
		t.Fatalf("body is nil")
	}
	if body.ContentType == "" {
		t.Errorf("empty content type")
	}
	if len(body.Content) == 0 {
		t.Errorf("empty content")
	}
}

// Ensure DefaultMakeNonce returns non-empty strings (sanity).
func TestDefaultMakeNonce(t *testing.T) {
	t.Parallel()

	if DefaultMakeNonce == nil {
		t.Fatalf("DefaultMakeNonce is nil")
	}
	got := DefaultMakeNonce()
	if got == "" {
		t.Errorf("DefaultMakeNonce returned empty string")
	}
}

