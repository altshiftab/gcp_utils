package http_context_extractor

import (
	"bufio"
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	motmedelHttpContext "github.com/Motmedel/utils_go/pkg/http/context"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
)

func TestMaskJws(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "valid JWS compact serialization",
			input: "header.payload.signature",
			want:  "header.payload.(MASKED)",
		},
		{
			name:  "valid JWS with realistic base64 parts",
			input: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature",
			want:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.(MASKED)",
		},
		{
			name:  "invalid JWS, not enough parts",
			input: "nodelimiters",
			want:  "(MASKED)",
		},
		{
			name:  "invalid JWS, only two parts",
			input: "header.payload",
			want:  "(MASKED)",
		},
		{
			name:  "empty string",
			input: "",
			want:  "(MASKED)",
		},
		{
			name:  "JWS with dots in signature",
			input: "a.b.c.d",
			want:  "a.b.(MASKED)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := maskJws(tc.input)
			if got != tc.want {
				t.Errorf("maskJws(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestMaskBasicAuth(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "valid basic auth credentials",
			input: base64.StdEncoding.EncodeToString([]byte("user:password")),
			want:  base64.StdEncoding.EncodeToString([]byte("user:")) + "(MASKED)",
		},
		{
			name:  "valid basic auth with empty password",
			input: base64.StdEncoding.EncodeToString([]byte("user:")),
			want:  base64.StdEncoding.EncodeToString([]byte("user:")) + "(MASKED)",
		},
		{
			name:  "valid basic auth with colon in password",
			input: base64.StdEncoding.EncodeToString([]byte("user:pass:word")),
			want:  base64.StdEncoding.EncodeToString([]byte("user:")) + "(MASKED)",
		},
		{
			name:  "invalid base64",
			input: "not-valid-base64!!!",
			want:  "(MASKED)",
		},
		{
			name:  "valid base64 but no colon separator",
			input: base64.StdEncoding.EncodeToString([]byte("nocolon")),
			want:  "(MASKED)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := maskBasicAuth(tc.input)
			if got != tc.want {
				t.Errorf("maskBasicAuth(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestMaskSetCookieHeader(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "cookie with JWS value",
			input: "session=header.payload.signature; Path=/; HttpOnly",
			want:  "session=header.payload.(MASKED); Path=/; HttpOnly",
		},
		{
			name:  "cookie with non-JWS value",
			input: "session=simplevalue; Path=/",
			want:  "session=(MASKED); Path=/",
		},
		{
			name:  "empty cookie value",
			input: "session=; Path=/",
			want:  "session=(MASKED); Path=/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := maskSetCookieHeader(tc.input)
			if got != tc.want {
				t.Errorf("maskSetCookieHeader(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestMaskCookieHeader(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "single cookie with JWS value",
			input: "session=header.payload.signature",
			want:  "session=header.payload.(MASKED)",
		},
		{
			name:  "multiple cookies",
			input: "a=x.y.z; b=p.q.r",
			want:  "a=x.y.(MASKED); b=p.q.(MASKED)",
		},
		{
			name:  "single cookie with non-JWS value",
			input: "session=simplevalue",
			want:  "session=(MASKED)",
		},
		{
			name:  "empty cookie header",
			input: "",
			want:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := maskCookieHeader(tc.input)
			if got != tc.want {
				t.Errorf("maskCookieHeader(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestExtractNormalizedHeaders(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		header     http.Header
		wantParts  []string // substrings that must appear
		avoidParts []string // substrings that must NOT appear
	}{
		{
			name:      "plain header",
			header:    http.Header{"X-Custom": {"value1"}},
			wantParts: []string{"X-Custom: value1\r\n"},
		},
		{
			name:      "Set-Cookie header with JWS",
			header:    http.Header{"Set-Cookie": {"token=a.b.c; Path=/; HttpOnly"}},
			wantParts: []string{"Set-Cookie: token=a.b.(MASKED); Path=/; HttpOnly\r\n"},
		},
		{
			name:      "Cookie header with JWS",
			header:    http.Header{"Cookie": {"sess=x.y.z"}},
			wantParts: []string{"Cookie: sess=x.y.(MASKED)\r\n"},
		},
		{
			name:       "X-Goog-Iap-Jwt-Assertion masked",
			header:     http.Header{"X-Goog-Iap-Jwt-Assertion": {"header.payload.signature"}},
			wantParts:  []string{"X-Goog-Iap-Jwt-Assertion: header.payload.(MASKED)\r\n"},
			avoidParts: []string{"signature"},
		},
		{
			name: "Authorization Bearer with JWS",
			header: http.Header{
				"Authorization": {"Bearer header.payload.signature"},
			},
			wantParts:  []string{"Authorization:"},
			avoidParts: []string{"signature"},
		},
		{
			name: "Authorization Basic",
			header: http.Header{
				"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))},
			},
			wantParts:  []string{"Authorization:"},
			avoidParts: []string{"pass"},
		},
		{
			name:      "empty header",
			header:    http.Header{},
			wantParts: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := extractNormalizedHeaders(tc.header)

			for _, part := range tc.wantParts {
				if !strings.Contains(got, part) {
					t.Errorf("extractNormalizedHeaders() = %q, want substring %q", got, part)
				}
			}

			for _, avoid := range tc.avoidParts {
				if strings.Contains(got, avoid) {
					t.Errorf("extractNormalizedHeaders() = %q, should not contain %q", got, avoid)
				}
			}
		})
	}
}

func TestExtractor_Handle_NilRecord(t *testing.T) {
	t.Parallel()
	e := &Extractor{}
	err := e.Handle(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected nil error for nil record, got %v", err)
	}
}

func TestExtractor_Handle_RequestId(t *testing.T) {
	t.Parallel()
	e := &Extractor{}
	ctx := context.WithValue(context.Background(), motmedelHttpContext.RequestIdContextKey, "test-request-id")
	record := &slog.Record{}

	err := e.Handle(ctx, record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the record has the request id attribute.
	found := false
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == "http" {
			a.Value.Resolve()
			for _, inner := range a.Value.Group() {
				if inner.Key == "request" {
					for _, attr := range inner.Value.Group() {
						if attr.Key == "id" && attr.Value.String() == "test-request-id" {
							found = true
							return false
						}
					}
				}
			}
		}
		return true
	})
	if !found {
		t.Error("expected http.request.id attribute in record")
	}
}

func TestExtractor_Handle_NoContext(t *testing.T) {
	t.Parallel()
	e := &Extractor{}
	record := &slog.Record{}

	err := e.Handle(context.Background(), record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractor_Handle_HttpContext(t *testing.T) {
	t.Parallel()

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET /test HTTP/1.1\r\nHost: example.com\r\nX-Custom: value\r\n\r\n",
	)))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": {"text/plain"}},
	}

	httpContext := &motmedelHttpTypes.HttpContext{
		Request:  req,
		Response: resp,
	}

	ctx := context.WithValue(context.Background(), motmedelHttpContext.HttpContextContextKey, httpContext)
	record := &slog.Record{}

	e := &Extractor{}
	err = e.Handle(ctx, record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the record has attributes added from the HTTP context.
	hasAttrs := false
	record.Attrs(func(a slog.Attr) bool {
		hasAttrs = true
		return true
	})
	if !hasAttrs {
		t.Error("expected attributes to be added from HTTP context")
	}
}

func TestExtractor_Handle_HttpContextWithHeaders(t *testing.T) {
	t.Parallel()

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET /test HTTP/1.1\r\nHost: example.com\r\nCookie: sess=a.b.c\r\n\r\n",
	)))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Set-Cookie": {"token=x.y.z; Path=/"}},
	}

	httpContext := &motmedelHttpTypes.HttpContext{
		Request:  req,
		Response: resp,
	}

	ctx := context.WithValue(context.Background(), motmedelHttpContext.HttpContextContextKey, httpContext)
	record := &slog.Record{}

	e := &Extractor{}
	err = e.Handle(ctx, record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractor_Handle_HttpContextNilRequest(t *testing.T) {
	t.Parallel()

	httpContext := &motmedelHttpTypes.HttpContext{
		Request:  nil,
		Response: nil,
	}

	ctx := context.WithValue(context.Background(), motmedelHttpContext.HttpContextContextKey, httpContext)
	record := &slog.Record{}

	e := &Extractor{}
	err := e.Handle(ctx, record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractor_Handle_HttpContextRequestNoHeaders(t *testing.T) {
	t.Parallel()

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
	)))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}

	httpContext := &motmedelHttpTypes.HttpContext{
		Request: req,
	}

	ctx := context.WithValue(context.Background(), motmedelHttpContext.HttpContextContextKey, httpContext)
	record := &slog.Record{}

	e := &Extractor{}
	err = e.Handle(ctx, record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractor_Handle_MessageNotOverwrittenWithoutRequest(t *testing.T) {
	t.Parallel()

	e := &Extractor{}
	record := &slog.Record{}
	record.Message = "original message"

	err := e.Handle(context.Background(), record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if record.Message != "original message" {
		t.Errorf("record.Message = %q, want %q", record.Message, "original message")
	}
}

func TestExtractor_Handle_HttpContextResponseNoHeaders(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     nil,
	}

	httpContext := &motmedelHttpTypes.HttpContext{
		Response: resp,
	}

	ctx := context.WithValue(context.Background(), motmedelHttpContext.HttpContextContextKey, httpContext)
	record := &slog.Record{}

	e := &Extractor{}
	err := e.Handle(ctx, record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
