package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	motmedelMux "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	endpointPkg "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/static_content"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
)

// styleSrcSources returns the set of style-src source strings from the mux's content security policy.
func styleSrcSources(t *testing.T, mux *motmedelMux.Mux) map[string]struct{} {
	t.Helper()

	csp, err := mux.GetContentSecurityPolicy()
	if err != nil {
		t.Fatalf("get content security policy: %v", err)
	}
	if csp == nil {
		t.Fatalf("content security policy is nil")
	}

	styleSrc := csp.GetStyleSrc()
	if styleSrc == nil {
		t.Fatalf("style-src directive is nil")
	}

	sources := make(map[string]struct{})
	for _, source := range styleSrc.Sources {
		sources[source.String()] = struct{}{}
	}

	return sources
}

// assertStyleSrcPatched asserts that style-src contains every hash (rendered as a CSP hash source), 'self',
// and 'unsafe-hashes' (the latter is required for the hashes to apply to inline style attributes).
func assertStyleSrcPatched(t *testing.T, sources map[string]struct{}, hashes []string) {
	t.Helper()

	for _, hash := range hashes {
		want := "'" + hash + "'"
		if _, found := sources[want]; !found {
			t.Errorf("style-src missing hash source %q", want)
		}
	}

	for _, keyword := range []string{"'self'", "'unsafe-hashes'"} {
		if _, found := sources[keyword]; !found {
			t.Errorf("style-src missing %s", keyword)
		}
	}
}

// getBody performs a GET against the test server without following redirects and returns the status and body.
func getBody(t *testing.T, serverUrl, path string) (int, string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverUrl+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpResponse, err := client.Do(request)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	defer func() {
		if err := httpResponse.Body.Close(); err != nil {
			t.Errorf("response body close: %v", err)
		}
	}()

	body, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return httpResponse.StatusCode, string(body)
}

func TestPatchChromeXmlRenderer(t *testing.T) {
	t.Parallel()

	mux := motmedelMux.New()
	if err := PatchChromeXmlRenderer(mux); err != nil {
		t.Fatalf("PatchChromeXmlRenderer: %v", err)
	}

	assertStyleSrcPatched(t, styleSrcSources(t, mux), chromeXmlHashes)
}

func TestPatchEdgePdfViewerRenderer(t *testing.T) {
	t.Parallel()

	mux := motmedelMux.New()
	if err := PatchEdgePdfViewerRenderer(mux); err != nil {
		t.Fatalf("PatchEdgePdfViewerRenderer: %v", err)
	}

	assertStyleSrcPatched(t, styleSrcSources(t, mux), edgePdfViewerHashes)
}

// TestPatchStyleSrcWithHashesNoExistingCsp exercises the fallback that parses the default content security
// policy when the mux has none set, and the branch that creates style-src from scratch.
func TestPatchStyleSrcWithHashesNoExistingCsp(t *testing.T) {
	t.Parallel()

	mux := motmedelMux.New()
	mux.DefaultDocumentHeaders[ContentSecurityPolicyHeader] = ""

	if err := patchStyleSrcWithHashes(mux, chromeXmlHashes...); err != nil {
		t.Fatalf("patchStyleSrcWithHashes: %v", err)
	}

	assertStyleSrcPatched(t, styleSrcSources(t, mux), chromeXmlHashes)
}

func TestPatchStyleSrcWithHashesNilMux(t *testing.T) {
	t.Parallel()

	if err := PatchChromeXmlRenderer(nil); err != nil {
		t.Errorf("PatchChromeXmlRenderer(nil): %v", err)
	}
	if err := PatchEdgePdfViewerRenderer(nil); err != nil {
		t.Errorf("PatchEdgePdfViewerRenderer(nil): %v", err)
	}
}

// TestPatchStyleSrcWithHashesIdempotent verifies that re-patching does not duplicate sources.
func TestPatchStyleSrcWithHashesIdempotent(t *testing.T) {
	t.Parallel()

	mux := motmedelMux.New()

	if err := PatchChromeXmlRenderer(mux); err != nil {
		t.Fatalf("PatchChromeXmlRenderer: %v", err)
	}
	first := len(styleSrcSources(t, mux))

	if err := PatchChromeXmlRenderer(mux); err != nil {
		t.Fatalf("PatchChromeXmlRenderer (second call): %v", err)
	}
	second := len(styleSrcSources(t, mux))

	if first != second {
		t.Errorf("expected idempotent style-src sources, got %d then %d", first, second)
	}
}

func TestPatchMuxProblemDetailConverter(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                string
		negotiation         *motmedelHttpTypes.ContentNegotiation
		expectedContentType string
	}{
		{
			name:                "problem+xml is rewritten to xml",
			negotiation:         &motmedelHttpTypes.ContentNegotiation{NegotiatedAccept: "application/problem+xml"},
			expectedContentType: "application/xml",
		},
		{
			name:                "json is left unchanged",
			negotiation:         nil,
			expectedContentType: "application/problem+json",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			mux := motmedelMux.New()
			PatchMuxProblemDetailConverter(mux)

			if mux.ProblemDetailConverter == nil {
				t.Fatalf("ProblemDetailConverter is nil")
			}

			_, contentType, err := mux.ProblemDetailConverter.Convert(
				problem_detail.New(http.StatusNotFound),
				testCase.negotiation,
			)
			if err != nil {
				t.Fatalf("convert: %v", err)
			}

			if contentType != testCase.expectedContentType {
				t.Errorf("got content type %q, expected %q", contentType, testCase.expectedContentType)
			}
		})
	}
}

func TestPatchMux(t *testing.T) {
	t.Parallel()

	mux := motmedelMux.New()
	if err := PatchMux(mux); err != nil {
		t.Fatalf("PatchMux: %v", err)
	}

	sources := styleSrcSources(t, mux)
	assertStyleSrcPatched(t, sources, chromeXmlHashes)
	assertStyleSrcPatched(t, sources, edgePdfViewerHashes)

	if mux.ProblemDetailConverter == nil {
		t.Errorf("PatchMux did not set ProblemDetailConverter")
	}
}

func TestPatchStrictTransportSecurity(t *testing.T) {
	t.Parallel()

	t.Run("sets header", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		if err := PatchStrictTransportSecurity(mux); err != nil {
			t.Fatalf("PatchStrictTransportSecurity: %v", err)
		}
		if got := mux.DefaultHeaders["Strict-Transport-Security"]; got != "max-age=31536000; includeSubDomains" {
			t.Errorf("got Strict-Transport-Security %q", got)
		}
	})

	t.Run("nil mux", func(t *testing.T) {
		t.Parallel()

		if err := PatchStrictTransportSecurity(nil); err != nil {
			t.Errorf("PatchStrictTransportSecurity(nil): %v", err)
		}
	})

	t.Run("nil default headers", func(t *testing.T) {
		t.Parallel()

		if err := PatchStrictTransportSecurity(&motmedelMux.Mux{}); err == nil {
			t.Errorf("expected error for nil default headers")
		}
	})
}

func TestPatchFedCm(t *testing.T) {
	t.Parallel()

	providerUrl := &url.URL{Scheme: "https", Host: "idp.example.com"}

	t.Run("patches csp and permissions policy", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		if err := PatchFedCm(mux, nil, []*url.URL{providerUrl}); err != nil {
			t.Fatalf("PatchFedCm: %v", err)
		}

		csp, err := mux.GetContentSecurityPolicy()
		if err != nil {
			t.Fatalf("get content security policy: %v", err)
		}

		connectSrc := csp.GetConnectSrc()
		if connectSrc == nil {
			t.Fatalf("connect-src directive is nil")
		}
		var hasSelf bool
		for _, source := range connectSrc.Sources {
			if source.String() == "'self'" {
				hasSelf = true
			}
		}
		if !hasSelf {
			t.Errorf("connect-src missing 'self'")
		}

		permissionsPolicy := mux.DefaultDocumentHeaders[PermissionsPolicyHeader]
		want := `identity-credentials-get=(self "https://idp.example.com")`
		if !strings.Contains(permissionsPolicy, want) {
			t.Errorf("Permissions-Policy %q does not contain %q", permissionsPolicy, want)
		}
	})

	t.Run("no providers is a no-op", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		before := mux.DefaultDocumentHeaders[PermissionsPolicyHeader]
		if err := PatchFedCm(mux, nil, nil); err != nil {
			t.Fatalf("PatchFedCm: %v", err)
		}
		if after := mux.DefaultDocumentHeaders[PermissionsPolicyHeader]; after != before {
			t.Errorf("Permissions-Policy changed: %q -> %q", before, after)
		}
	})

	// When the mux has no content security policy set, FedCm must fall back to the default policy rather than
	// silently dropping the connect-src allowance for the provider.
	t.Run("no existing csp falls back to default", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		mux.DefaultDocumentHeaders[ContentSecurityPolicyHeader] = ""

		if err := PatchFedCm(mux, nil, []*url.URL{providerUrl}); err != nil {
			t.Fatalf("PatchFedCm: %v", err)
		}

		csp, err := mux.GetContentSecurityPolicy()
		if err != nil {
			t.Fatalf("get content security policy: %v", err)
		}
		if csp == nil {
			t.Fatalf("content security policy is nil; connect-src was not applied")
		}
		if csp.GetConnectSrc() == nil {
			t.Errorf("connect-src not applied when no CSP was set")
		}
	})

	t.Run("nil mux", func(t *testing.T) {
		t.Parallel()

		if err := PatchFedCm(nil, nil, []*url.URL{providerUrl}); err != nil {
			t.Errorf("PatchFedCm(nil): %v", err)
		}
	})
}

func TestPatchTrustedTypes(t *testing.T) {
	t.Parallel()

	t.Run("adds directives", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		if err := PatchTrustedTypes(mux, "my-policy"); err != nil {
			t.Fatalf("PatchTrustedTypes: %v", err)
		}

		csp := mux.DefaultDocumentHeaders[ContentSecurityPolicyHeader]
		if !strings.Contains(csp, "require-trusted-types-for 'script'") {
			t.Errorf("CSP %q missing require-trusted-types-for", csp)
		}
		if !strings.Contains(csp, "trusted-types my-policy") {
			t.Errorf("CSP %q missing trusted-types my-policy", csp)
		}
	})

	t.Run("empty policies is a no-op", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		before := mux.DefaultDocumentHeaders[ContentSecurityPolicyHeader]
		if err := PatchTrustedTypes(mux); err != nil {
			t.Fatalf("PatchTrustedTypes: %v", err)
		}
		if after := mux.DefaultDocumentHeaders[ContentSecurityPolicyHeader]; after != before {
			t.Errorf("CSP changed: %q -> %q", before, after)
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		if err := PatchTrustedTypes(mux, "my-policy"); err != nil {
			t.Fatalf("PatchTrustedTypes: %v", err)
		}
		first := mux.DefaultDocumentHeaders[ContentSecurityPolicyHeader]
		if err := PatchTrustedTypes(mux, "my-policy"); err != nil {
			t.Fatalf("PatchTrustedTypes (second call): %v", err)
		}
		if second := mux.DefaultDocumentHeaders[ContentSecurityPolicyHeader]; second != first {
			t.Errorf("CSP not idempotent: %q -> %q", first, second)
		}
	})

	t.Run("nil mux", func(t *testing.T) {
		t.Parallel()

		if err := PatchTrustedTypes(nil, "my-policy"); err == nil {
			t.Errorf("expected error for nil mux")
		}
	})
}

func TestMakeSitemapXmlUrl(t *testing.T) {
	t.Parallel()

	t.Run("nil static content data", func(t *testing.T) {
		t.Parallel()

		got, err := makeSitemapXmlUrl(nil, "https://example.com/")
		if err != nil {
			t.Fatalf("makeSitemapXmlUrl: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil url, got %+v", got)
		}
	})

	t.Run("empty location", func(t *testing.T) {
		t.Parallel()

		if _, err := makeSitemapXmlUrl(&static_content.StaticContentData{}, ""); err == nil {
			t.Errorf("expected error for empty location")
		}
	})

	t.Run("non-document", func(t *testing.T) {
		t.Parallel()

		data := &static_content.StaticContentData{
			Headers: []*response.HeaderEntry{{Name: "Last-Modified", Value: "Mon, 01 Jan 2024 00:00:00 GMT"}},
		}
		got, err := makeSitemapXmlUrl(data, "https://example.com/")
		if err != nil {
			t.Fatalf("makeSitemapXmlUrl: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil url for non-document, got %+v", got)
		}
	})

	t.Run("document with last-modified", func(t *testing.T) {
		t.Parallel()

		data := &static_content.StaticContentData{
			Headers: []*response.HeaderEntry{
				{Name: "Content-Type", Value: "text/html"},
				{Name: "Last-Modified", Value: "Mon, 01 Jan 2024 00:00:00 GMT"},
			},
		}
		got, err := makeSitemapXmlUrl(data, "https://example.com/page")
		if err != nil {
			t.Fatalf("makeSitemapXmlUrl: %v", err)
		}
		if got == nil {
			t.Fatalf("expected non-nil url")
		}
		if got.Loc != "https://example.com/page" {
			t.Errorf("got Loc %q", got.Loc)
		}
		if !strings.HasPrefix(got.Lastmod, "2024-01-01T00:00:00") {
			t.Errorf("got Lastmod %q, expected 2024-01-01T00:00:00 prefix", got.Lastmod)
		}
	})

	t.Run("content type with parameters is a document", func(t *testing.T) {
		t.Parallel()

		data := &static_content.StaticContentData{
			Headers: []*response.HeaderEntry{{Name: "Content-Type", Value: "text/html; charset=utf-8"}},
		}
		got, err := makeSitemapXmlUrl(data, "https://example.com/page")
		if err != nil {
			t.Fatalf("makeSitemapXmlUrl: %v", err)
		}
		if got == nil {
			t.Errorf("expected non-nil url for text/html with charset parameter")
		}
	})

	t.Run("non-indexable content type is excluded", func(t *testing.T) {
		t.Parallel()

		for _, contentType := range []string{"text/css", "application/javascript", "image/png"} {
			data := &static_content.StaticContentData{
				Headers: []*response.HeaderEntry{{Name: "Content-Type", Value: contentType}},
			}
			got, err := makeSitemapXmlUrl(data, "https://example.com/asset")
			if err != nil {
				t.Fatalf("makeSitemapXmlUrl (%s): %v", contentType, err)
			}
			if got != nil {
				t.Errorf("expected nil url for content type %q, got %+v", contentType, got)
			}
		}
	})

	t.Run("document without last-modified", func(t *testing.T) {
		t.Parallel()

		data := &static_content.StaticContentData{
			Headers: []*response.HeaderEntry{{Name: "Content-Type", Value: "text/html"}},
		}
		got, err := makeSitemapXmlUrl(data, "https://example.com/page")
		if err != nil {
			t.Fatalf("makeSitemapXmlUrl: %v", err)
		}
		if got == nil {
			t.Fatalf("expected non-nil url")
		}
		if got.Lastmod != "" {
			t.Errorf("expected empty Lastmod, got %q", got.Lastmod)
		}
	})
}

func TestPatchOtherDomainSecurityTxt(t *testing.T) {
	t.Parallel()

	t.Run("registers redirects", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		securityTxtUrl := &url.URL{Scheme: "https", Host: "example.com", Path: "/.well-known/security.txt"}
		if err := PatchOtherDomainSecurityTxt(mux, securityTxtUrl); err != nil {
			t.Fatalf("PatchOtherDomainSecurityTxt: %v", err)
		}

		server := httptest.NewServer(mux)
		defer server.Close()

		for _, path := range []string{"/security.txt", "/.well-known/security.txt"} {
			muxTesting.TestArgs(t, &muxTesting.Args{
				Method:             http.MethodGet,
				Path:               path,
				ExpectedStatusCode: http.StatusPermanentRedirect,
				ExpectedHeaders:    [][2]string{{"Location", "https://example.com/.well-known/security.txt"}},
			}, server.URL)
		}
	})

	t.Run("nil mux", func(t *testing.T) {
		t.Parallel()

		if err := PatchOtherDomainSecurityTxt(nil, &url.URL{Scheme: "https", Host: "example.com"}); err != nil {
			t.Errorf("PatchOtherDomainSecurityTxt(nil): %v", err)
		}
	})

	t.Run("nil security txt url", func(t *testing.T) {
		t.Parallel()

		if err := PatchOtherDomainSecurityTxt(motmedelMux.New(), nil); err == nil {
			t.Errorf("expected error for nil security txt url")
		}
	})
}

func TestPatchSecurityTxt(t *testing.T) {
	t.Parallel()

	t.Run("localhost serves content", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		baseUrl := &url.URL{Scheme: "https", Host: "localhost"}
		if err := PatchSecurityTxt(mux, baseUrl); err != nil {
			t.Fatalf("PatchSecurityTxt: %v", err)
		}

		server := httptest.NewServer(mux)
		defer server.Close()

		muxTesting.TestArgs(t, &muxTesting.Args{
			Method:             http.MethodGet,
			Path:               "/security.txt",
			ExpectedStatusCode: http.StatusPermanentRedirect,
			ExpectedHeaders:    [][2]string{{"Location", "/.well-known/security.txt"}},
		}, server.URL)

		status, body := getBody(t, server.URL, "/.well-known/security.txt")
		if status != http.StatusOK {
			t.Errorf("got status %d for security.txt", status)
		}
		if !strings.Contains(body, "Contact: mailto:security@localhost") {
			t.Errorf("security.txt body missing contact: %q", body)
		}
	})

	t.Run("registered domain serves content", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		baseUrl := &url.URL{Scheme: "https", Host: "example.com"}
		if err := PatchSecurityTxt(mux, baseUrl); err != nil {
			t.Fatalf("PatchSecurityTxt: %v", err)
		}

		server := httptest.NewServer(mux)
		defer server.Close()

		status, body := getBody(t, server.URL, "/.well-known/security.txt")
		if status != http.StatusOK {
			t.Errorf("got status %d for security.txt", status)
		}
		if !strings.Contains(body, "Contact: mailto:security@example.com") {
			t.Errorf("security.txt body missing contact: %q", body)
		}
	})

	t.Run("subdomain redirects to registered domain", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		baseUrl := &url.URL{Scheme: "https", Host: "www.example.com"}
		if err := PatchSecurityTxt(mux, baseUrl); err != nil {
			t.Fatalf("PatchSecurityTxt: %v", err)
		}

		server := httptest.NewServer(mux)
		defer server.Close()

		muxTesting.TestArgs(t, &muxTesting.Args{
			Method:             http.MethodGet,
			Path:               "/.well-known/security.txt",
			ExpectedStatusCode: http.StatusPermanentRedirect,
			ExpectedHeaders:    [][2]string{{"Location", "https://example.com/.well-known/security.txt"}},
		}, server.URL)
	})

	t.Run("nil mux", func(t *testing.T) {
		t.Parallel()

		if err := PatchSecurityTxt(nil, &url.URL{Scheme: "https", Host: "example.com"}); err != nil {
			t.Errorf("PatchSecurityTxt(nil): %v", err)
		}
	})

	t.Run("nil base url", func(t *testing.T) {
		t.Parallel()

		if err := PatchSecurityTxt(motmedelMux.New(), nil); err == nil {
			t.Errorf("expected error for nil base url")
		}
	})
}

func TestPatchErrorReporting(t *testing.T) {
	t.Parallel()

	t.Run("sets headers", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		baseUrl := &url.URL{Scheme: "https", Host: "example.com"}
		if err := PatchErrorReporting(mux, baseUrl); err != nil {
			t.Fatalf("PatchErrorReporting: %v", err)
		}

		if got := mux.DefaultHeaders["Report-To"]; !strings.Contains(got, NetworkErrorLoggingEndpoint) {
			t.Errorf("Report-To %q missing %q", got, NetworkErrorLoggingEndpoint)
		}
		if got := mux.DefaultHeaders["NEL"]; got == "" {
			t.Errorf("NEL header not set")
		}

		reportingEndpoints := mux.DefaultDocumentHeaders["Reporting-Endpoints"]
		if !strings.Contains(reportingEndpoints, CspReportToToken) || !strings.Contains(reportingEndpoints, IntegrityEndpointToken) {
			t.Errorf("Reporting-Endpoints %q missing expected tokens", reportingEndpoints)
		}

		csp := mux.DefaultDocumentHeaders[ContentSecurityPolicyHeader]
		if !strings.Contains(csp, "report-to "+CspReportToToken) {
			t.Errorf("CSP %q missing report-to directive", csp)
		}
		if !strings.Contains(csp, "report-uri "+CspReportUriEndpoint) {
			t.Errorf("CSP %q missing report-uri directive", csp)
		}

		if got := mux.DefaultDocumentHeaders[IntegrityPolicyHeader]; !strings.Contains(got, IntegrityEndpointToken) {
			t.Errorf("Integrity-Policy %q missing endpoint token", got)
		}
	})

	t.Run("nil mux", func(t *testing.T) {
		t.Parallel()

		if err := PatchErrorReporting(nil, &url.URL{Scheme: "https", Host: "example.com"}); err != nil {
			t.Errorf("PatchErrorReporting(nil): %v", err)
		}
	})

	t.Run("nil base url", func(t *testing.T) {
		t.Parallel()

		if err := PatchErrorReporting(motmedelMux.New(), nil); err == nil {
			t.Errorf("expected error for nil base url")
		}
	})
}

func TestPatchCrawlable(t *testing.T) {
	t.Parallel()

	t.Run("generates sitemap and robots", func(t *testing.T) {
		t.Parallel()

		baseUrl := &url.URL{Scheme: "https", Host: "example.com"}
		documentEndpoint := &endpointPkg.Endpoint{
			Path:   "/page",
			Method: http.MethodGet,
			Public: true,
			StaticContent: &static_content.StaticContent{
				StaticContentData: static_content.StaticContentData{
					Data: []byte("<html></html>"),
					Headers: muxUtils.MakeStaticContentHeaders(
						"text/html",
						"no-cache",
						"\"etag\"",
						"Mon, 01 Jan 2024 00:00:00 GMT",
					),
				},
			},
		}

		mux := motmedelMux.New()
		if err := PatchCrawlable(mux, baseUrl, []*endpointPkg.Endpoint{documentEndpoint}); err != nil {
			t.Fatalf("PatchCrawlable: %v", err)
		}

		server := httptest.NewServer(mux)
		defer server.Close()

		status, robots := getBody(t, server.URL, "/robots.txt")
		if status != http.StatusOK {
			t.Errorf("got status %d for robots.txt", status)
		}
		if !strings.Contains(strings.ToLower(robots), "sitemap") {
			t.Errorf("robots.txt missing sitemap reference: %q", robots)
		}

		status, sitemap := getBody(t, server.URL, "/sitemap.xml")
		if status != http.StatusOK {
			t.Errorf("got status %d for sitemap.xml", status)
		}
		if !strings.Contains(sitemap, "https://example.com/page") {
			t.Errorf("sitemap.xml missing page location: %q", sitemap)
		}
	})

	t.Run("nil mux", func(t *testing.T) {
		t.Parallel()

		if err := PatchCrawlable(nil, &url.URL{Scheme: "https", Host: "example.com"}, nil); err != nil {
			t.Errorf("PatchCrawlable(nil): %v", err)
		}
	})

	t.Run("nil base url", func(t *testing.T) {
		t.Parallel()

		if err := PatchCrawlable(motmedelMux.New(), nil, nil); err == nil {
			t.Errorf("expected error for nil base url")
		}
	})
}

func TestPatchHttpServiceMux(t *testing.T) {
	t.Parallel()

	t.Run("localhost skips strict transport security", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		baseUrl := &url.URL{Scheme: "http", Host: "localhost"}
		if err := PatchHttpServiceMux(mux, baseUrl); err != nil {
			t.Fatalf("PatchHttpServiceMux: %v", err)
		}

		if _, found := mux.DefaultHeaders["Strict-Transport-Security"]; found {
			t.Errorf("did not expect Strict-Transport-Security for localhost")
		}
		if mux.DefaultHeaders["Report-To"] == "" {
			t.Errorf("expected error reporting to be applied")
		}
	})

	t.Run("non-localhost sets strict transport security", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		baseUrl := &url.URL{Scheme: "https", Host: "example.com"}
		if err := PatchHttpServiceMux(mux, baseUrl); err != nil {
			t.Fatalf("PatchHttpServiceMux: %v", err)
		}

		if mux.DefaultHeaders["Strict-Transport-Security"] == "" {
			t.Errorf("expected Strict-Transport-Security for non-localhost")
		}
	})

	t.Run("nil mux", func(t *testing.T) {
		t.Parallel()

		if err := PatchHttpServiceMux(nil, &url.URL{Scheme: "https", Host: "example.com"}); err == nil {
			t.Errorf("expected error for nil mux")
		}
	})

	t.Run("nil base url", func(t *testing.T) {
		t.Parallel()

		if err := PatchHttpServiceMux(motmedelMux.New(), nil); err == nil {
			t.Errorf("expected error for nil base url")
		}
	})
}

func TestPatchPublicHttpServiceMux(t *testing.T) {
	t.Parallel()

	t.Run("applies public patches", func(t *testing.T) {
		t.Parallel()

		mux := motmedelMux.New()
		baseUrl := &url.URL{Scheme: "https", Host: "example.com"}
		if err := PatchPublicHttpServiceMux(mux, baseUrl); err != nil {
			t.Fatalf("PatchPublicHttpServiceMux: %v", err)
		}

		if mux.ProblemDetailConverter == nil {
			t.Fatalf("expected ProblemDetailConverter to be set")
		}
		// The shared converter rewrites problem+xml to xml.
		_, contentType, err := mux.ProblemDetailConverter.Convert(
			problem_detail.New(http.StatusNotFound),
			&motmedelHttpTypes.ContentNegotiation{NegotiatedAccept: "application/problem+xml"},
		)
		if err != nil {
			t.Fatalf("convert: %v", err)
		}
		if contentType != "application/xml" {
			t.Errorf("got content type %q, expected application/xml", contentType)
		}

		if mux.DefaultHeaders["Strict-Transport-Security"] == "" {
			t.Errorf("expected Strict-Transport-Security to be set")
		}

		server := httptest.NewServer(mux)
		defer server.Close()

		if status, _ := getBody(t, server.URL, "/robots.txt"); status != http.StatusOK {
			t.Errorf("got status %d for robots.txt", status)
		}
		if status, _ := getBody(t, server.URL, "/.well-known/security.txt"); status != http.StatusOK {
			t.Errorf("got status %d for security.txt", status)
		}
	})

	t.Run("nil mux", func(t *testing.T) {
		t.Parallel()

		if err := PatchPublicHttpServiceMux(nil, &url.URL{Scheme: "https", Host: "example.com"}); err == nil {
			t.Errorf("expected error for nil mux")
		}
	})

	t.Run("nil base url", func(t *testing.T) {
		t.Parallel()

		if err := PatchPublicHttpServiceMux(motmedelMux.New(), nil); err == nil {
			t.Errorf("expected error for nil base url")
		}
	})
}
