package http

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelEnv "github.com/Motmedel/utils_go/pkg/env"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelHttpContext "github.com/Motmedel/utils_go/pkg/http/context"
	motmedelMux "github.com/Motmedel/utils_go/pkg/http/mux"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader"
	bodyParserAdapter "github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser/adapter"
	jsonSchemaBodyParser "github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser/json_schema_body_parser"
	endpointPkg "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/static_content"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_writer"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	contentSecurityPolicyParsing "github.com/Motmedel/utils_go/pkg/http/parsing/headers/content_security_policy"
	contentTypeParsing "github.com/Motmedel/utils_go/pkg/http/parsing/headers/content_type"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	"github.com/Motmedel/utils_go/pkg/http/types/content_security_policy"
	"github.com/Motmedel/utils_go/pkg/http/types/integrity_policy"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/reporting_api"
	motmedelHttpTypesSitemapxml "github.com/Motmedel/utils_go/pkg/http/types/sitemapxml"
	motmedelHttpUtils "github.com/Motmedel/utils_go/pkg/http/utils"
	cspUtils "github.com/Motmedel/utils_go/pkg/http/utils/content_security_policy"
	motmedelJson "github.com/Motmedel/utils_go/pkg/json"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"github.com/Motmedel/utils_go/pkg/net/types/domain_parts"
	"github.com/Motmedel/utils_go/pkg/schema"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/types/js_error_report"
)

const (
	PermissionsPolicyHeader     = "Permissions-Policy"
	ContentSecurityPolicyHeader = "Content-Security-Policy"
	IntegrityPolicyHeader       = "Integrity-Policy"
	CspReportToEndpoint         = "/api/report/csp-report-to"
	CspReportUriEndpoint        = "/api/report/csp-report-uri"
	NetworkErrorLoggingEndpoint = "/api/report/network-error-logging"
	IntegrityEndpoint           = "/api/report/integrity-endpoint"
	CspReportToToken            = "csp-report-to"
	IntegrityEndpointToken      = "integrity-endpoint"
)

var chromeXmlHashes = []string{
	"sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
	"sha256-p08VBe6m5i8+qtXWjnH/AN3klt1l4uoOLsjNn8BjdQo=",
}

var edgePdfViewerHashes = []string{
	"sha256-YBgjA+VjFtAXSIPo7m2n1vE7Z2+4KoNTMJRNxrNV1iE=",
	"sha256-tbWZ4NP1341cpcrZVDn7B3o9bt/muXgduILAnC0Zbaw=",
}

func PatchMuxProblemDetailConverter(mux *motmedelMux.Mux) {
	if mux == nil {
		return
	}

	mux.ProblemDetailConverter = response_error.ProblemDetailConverterFunction(
		func(detail *problem_detail.Detail, negotiation *motmedelHttpTypes.ContentNegotiation) ([]byte, string, error) {
			data, contentType, err := response_error.ConvertProblemDetail(detail, negotiation)
			if err != nil {
				return nil, "", fmt.Errorf("convert problem detail: %w", err)
			}
			if contentType == "application/problem+xml" {
				contentType = "application/xml"
			}
			return data, contentType, nil
		},
	)
}

func patchStyleSrcWithHashes(mux *motmedelMux.Mux, hashes ...string) error {
	if mux == nil {
		return nil
	}

	csp, err := mux.GetContentSecurityPolicy()
	if err != nil {
		return fmt.Errorf("mux get content security policy: %w", err)
	}
	if csp == nil {
		csp, err = contentSecurityPolicyParsing.Parse([]byte(response_writer.DefaultContentSecurityPolicyString))
		if err != nil {
			return fmt.Errorf("parse content security policy: %w", err)
		}
	}
	if csp == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("content security policy"))
	}

	if err := cspUtils.PatchCspStyleSrcWithHash(csp, hashes...); err != nil {
		return fmt.Errorf("patch csp style src with hash: %w", err)
	}

	// CSP hashes only match the body of `<style>` elements, not inline `style` attributes. The Chrome XML and
	// Edge PDF viewers style their output via `style` attributes, so 'unsafe-hashes' is required for the
	// hashes above to take effect (it permits only attribute content matching a listed hash, unlike the much
	// broader 'unsafe-inline'). 'self' is also ensured for the viewers' linked stylesheets.
	requiredKeywords := []string{"self", "unsafe-hashes"}

	if styleSrc := csp.GetStyleSrc(); styleSrc != nil {
		sourceMap := make(map[string]struct{})
		for _, source := range styleSrc.Sources {
			sourceMap[source.String()] = struct{}{}
		}
		for _, keyword := range requiredKeywords {
			keywordSource := &content_security_policy.KeywordSource{Keyword: keyword}
			if _, found := sourceMap[keywordSource.String()]; !found {
				styleSrc.Sources = append(styleSrc.Sources, keywordSource)
			}
		}
	} else {
		// If style-src did not exist, create it with the required keywords.
		sources := make([]content_security_policy.SourceI, 0, len(requiredKeywords))
		for _, keyword := range requiredKeywords {
			sources = append(sources, &content_security_policy.KeywordSource{Keyword: keyword})
		}
		csp.Directives = append(csp.Directives, &content_security_policy.StyleSrcDirective{
			SourceDirective: content_security_policy.SourceDirective{Sources: sources},
		})
	}

	if err := mux.SetContentSecurityPolicy(csp); err != nil {
		return fmt.Errorf("set content security policy: %w", err)
	}

	return nil
}

func PatchChromeXmlRenderer(mux *motmedelMux.Mux) error {
	if err := patchStyleSrcWithHashes(mux, chromeXmlHashes...); err != nil {
		return fmt.Errorf("patch style src with hashes: %w", err)
	}

	return nil
}

func PatchEdgePdfViewerRenderer(mux *motmedelMux.Mux) error {
	if err := patchStyleSrcWithHashes(mux, edgePdfViewerHashes...); err != nil {
		return fmt.Errorf("patch style src with hashes: %w", err)
	}

	return nil
}

func PatchMux(mux *motmedelMux.Mux) error {
	if mux == nil {
		return nil
	}

	PatchMuxProblemDetailConverter(mux)

	if err := PatchChromeXmlRenderer(mux); err != nil {
		return fmt.Errorf("patch chrome xml renderer: %w", err)
	}

	if err := PatchEdgePdfViewerRenderer(mux); err != nil {
		return fmt.Errorf("patch edge pdf viewer renderer: %w", err)
	}

	if motmedelEnv.GetEnvWithDefault("LOG_LEVEL", "INFO") == "DEBUG" {
		mux.DoneCallback = func(ctx context.Context) {
			slog.DebugContext(
				ctx,
				"An HTTP response was served.",
				slog.Group(
					"event",
					slog.String("action", "http_response_served"),
					slog.String("reason", "An HTTP response was served."),
				),
			)
		}
	}

	return nil
}

// sitemapContentTypes are the response content types whose endpoints are eligible for inclusion in the
// sitemap, i.e. the document types search engines crawl and index.
var sitemapContentTypes = map[string]struct{}{
	"text/html":             {},
	"application/xhtml+xml": {},
	"application/pdf":       {},
}

func makeSitemapXmlUrl(
	staticContentData *static_content.StaticContentData,
	location string,
) (*motmedelHttpTypesSitemapxml.Url, error) {
	if staticContentData == nil {
		return nil, nil
	}

	if location == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("location"))
	}

	var lastModified string
	var isDocument bool
	for _, header := range staticContentData.Headers {
		switch strings.ToLower(header.Name) {
		case "content-type":
			if contentType, err := contentTypeParsing.Parse([]byte(header.Value)); err == nil && contentType != nil {
				if _, found := sitemapContentTypes[contentType.GetFullType(true)]; found {
					isDocument = true
				}
			}
		case "last-modified":
			lastModified = header.Value
		}

		if isDocument && lastModified != "" {
			break
		}
	}

	if !isDocument {
		return nil, nil
	}

	var formattedLastModified string
	if lastModified != "" {
		parsedTime, err := time.Parse(time.RFC1123, lastModified)
		if err != nil {
			return nil, motmedelErrors.NewWithTrace(fmt.Errorf("time parse: %w", err), lastModified)
		}

		formattedLastModified = parsedTime.Format(time.RFC3339)
	}

	return &motmedelHttpTypesSitemapxml.Url{Loc: location, Lastmod: formattedLastModified}, nil
}

func PatchCrawlable(
	mux *motmedelMux.Mux,
	baseUrl *url.URL,
	endpoints []*endpointPkg.Endpoint,
) error {
	if mux == nil {
		return nil
	}

	if baseUrl == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("base url"))
	}

	nowUtc := time.Now().UTC()

	var sitemapXmlUrls []*motmedelHttpTypesSitemapxml.Url

	for _, endpoint := range endpoints {
		staticContent := endpoint.StaticContent
		if staticContent == nil {
			continue
		}

		path := endpoint.Path
		pathUrl := baseUrl.JoinPath(path)
		if pathUrl == nil {
			return motmedelErrors.NewWithTrace(nil_error.New("path url"))
		}

		staticContentData := staticContent.StaticContentData
		location := pathUrl.String()

		sitemapXmlUrl, err := makeSitemapXmlUrl(&staticContentData, location)
		if err != nil {
			return motmedelErrors.NewWithTrace(
				fmt.Errorf("make sitemapxml url: %w", err),
				staticContentData, location,
			)
		}
		if sitemapXmlUrl != nil {
			sitemapXmlUrls = append(sitemapXmlUrls, sitemapXmlUrl)
		}
	}

	var otherRecords [][2]string
	if len(sitemapXmlUrls) > 0 {
		sitemapXmlUrlSet := motmedelHttpTypesSitemapxml.UrlSet{
			Xmlns: "https://www.sitemaps.org/schemas/sitemap/0.9",
			Urls:  sitemapXmlUrls,
		}
		sitemapXmlUrlSetData, err := xml.Marshal(sitemapXmlUrlSet)
		if err != nil {
			return motmedelErrors.NewWithTrace(fmt.Errorf("xml marshal: %w", err), sitemapXmlUrlSet)
		}

		sitemapXmlData := append([]byte(xml.Header), sitemapXmlUrlSetData...)
		sitemapXmlEtag := motmedelHttpUtils.MakeStrongEtag(sitemapXmlData)
		sitemapXmlLastModified := nowUtc.Format("Mon, 02 Jan 2006 15:04:05") + " GMT"
		sitemapXmlUrl := baseUrl.JoinPath("/sitemap.xml")
		if sitemapXmlUrl == nil {
			return motmedelErrors.NewWithTrace(nil_error.New("sitemap xml url"))
		}

		mux.Add(
			&endpointPkg.Endpoint{
				Path:   "/sitemap.xml",
				Method: http.MethodGet,
				StaticContent: &static_content.StaticContent{
					StaticContentData: static_content.StaticContentData{
						Data:         sitemapXmlData,
						Etag:         sitemapXmlEtag,
						LastModified: sitemapXmlLastModified,
						Headers: muxUtils.MakeStaticContentHeaders(
							"application/xml",
							"no-cache",
							sitemapXmlEtag,
							sitemapXmlLastModified,
						),
					},
				},
				Public: true,
			},
		)

		otherRecords = [][2]string{{"Sitemap", sitemapXmlUrl.String()}}
	}

	mux.Add(
		endpointPkg.NewRobotsTxt(
			&motmedelHttpTypes.RobotsTxt{
				Groups: []*motmedelHttpTypes.RobotsTxtGroup{
					{UserAgents: []string{"*"}, Disallowed: []string{"/"}},
					{
						UserAgents:   []string{"Googlebot", "Bingbot", "Applebot", "DuckDuckBot", "archive.org_bot"},
						Disallowed:   []string{"/api/"},
						OtherRecords: otherRecords,
					},
				},
			},
		),
	)

	return nil
}

func PatchStrictTransportSecurity(mux *motmedelMux.Mux) error {
	if mux == nil {
		return nil
	}

	defaultHeaders := mux.DefaultHeaders
	if defaultHeaders == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("default headers"))
	}

	// TODO: Is it okay to include `includeSubdomains` even when the domain is not a top-level domain?
	defaultHeaders["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

	return nil
}

func PatchErrorReporting(mux *motmedelMux.Mux, baseUrl *url.URL) error {
	if mux == nil {
		return nil
	}

	if baseUrl == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("base url"))
	}

	defaultHeaders := mux.DefaultHeaders
	if defaultHeaders == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("default headers"))
	}

	defaultDocumentHeaders := mux.DefaultDocumentHeaders
	if defaultDocumentHeaders == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("default document headers"))
	}

	defaultHeaders["Report-To"] = fmt.Sprintf(
		"{\"group\": \"network-error-logging\", \"max-age\": 10886400, \"endpoints\": [{\"url\": \"%s%s\"}]}",
		baseUrl.String(),
		NetworkErrorLoggingEndpoint,
	)
	defaultHeaders["NEL"] = `{"report_to": "network-error-logging", "max_age": 10886400}`
	defaultDocumentHeaders["Reporting-Endpoints"] = fmt.Sprintf(
		"%s=\"%s\", %s=\"%s\"",
		CspReportToToken,
		CspReportToEndpoint,
		IntegrityEndpointToken,
		IntegrityEndpoint,
	)

	var contentSecurityPolicy *content_security_policy.ContentSecurityPolicy
	if contentSecurityPolicyString := defaultDocumentHeaders[ContentSecurityPolicyHeader]; contentSecurityPolicyString != "" {
		var err error
		contentSecurityPolicy, err = contentSecurityPolicyParsing.Parse(
			[]byte(contentSecurityPolicyString),
		)
		if err != nil {
			return motmedelErrors.New(
				fmt.Errorf("parse content security policy: %w", err),
				contentSecurityPolicyString,
			)
		}

		if reportToDirective := contentSecurityPolicy.GetReportTo(); reportToDirective != nil {
			reportToDirective.Token = CspReportToToken
		} else {
			contentSecurityPolicy.Directives = append(
				contentSecurityPolicy.Directives,
				&content_security_policy.ReportToDirective{Token: CspReportToToken},
			)
		}

		if reportUriDirective := contentSecurityPolicy.GetReportUri(); reportUriDirective != nil {
			if !slices.Contains(reportUriDirective.UriReferences, CspReportUriEndpoint) {
				reportUriDirective.UriReferences = append(
					reportUriDirective.UriReferences,
					CspReportUriEndpoint,
				)
			}
		} else {
			contentSecurityPolicy.Directives = append(
				contentSecurityPolicy.Directives,
				&content_security_policy.ReportUriDirective{
					UriReferences: []string{CspReportUriEndpoint},
				},
			)
		}
	} else {
		contentSecurityPolicy = &content_security_policy.ContentSecurityPolicy{
			Directives: []content_security_policy.DirectiveI{
				&content_security_policy.ReportToDirective{Token: CspReportToToken},
				&content_security_policy.ReportUriDirective{UriReferences: []string{CspReportUriEndpoint}},
			},
		}
	}

	defaultDocumentHeaders[ContentSecurityPolicyHeader] = contentSecurityPolicy.String()

	defaultDocumentHeaders[IntegrityPolicyHeader] = fmt.Sprintf(
		"blocked-destinations=(script), endpoints=(%s)",
		IntegrityEndpointToken,
	)

	cspReportToBodyParser, err := jsonSchemaBodyParser.New[[]*reporting_api.Report[*content_security_policy.CSPViolationReportBody]]()
	if err != nil {
		return motmedelErrors.New(
			fmt.Errorf("json schema body parser new (csp report to): %w", err),
		)
	}

	cspReportUriBodyParser, err := jsonSchemaBodyParser.New[*content_security_policy.ReportEnvelope]()
	if err != nil {
		return motmedelErrors.New(
			fmt.Errorf("json schema body parser new (csp report uri): %w", err),
		)
	}

	integrityPolicyBodyParser, err := jsonSchemaBodyParser.New[[]*reporting_api.Report[*integrity_policy.IntegrityViolationReportBody]]()
	if err != nil {
		return motmedelErrors.New(
			fmt.Errorf("json schema body parser new (integrity policy): %w", err),
		)
	}

	errorBodyParser, err := jsonSchemaBodyParser.New[*js_error_report.ErrorBody]()
	if err != nil {
		return motmedelErrors.New(
			fmt.Errorf("json schema body parser new (error body): %w", err),
		)
	}

	unhandledRejectionBodyParser, err := jsonSchemaBodyParser.New[*js_error_report.BaseErrorBody]()
	if err != nil {
		return motmedelErrors.New(
			fmt.Errorf("json schema body parser new (unhandled rejection body): %w", err),
		)
	}

	mux.Add(
		&endpointPkg.Endpoint{
			Public: true,
			Path:   CspReportToEndpoint,
			Method: http.MethodPost,
			BodyLoader: &body_loader.Loader{
				ContentType: "application/reports+json",
				MaxBytes:    8192,
				Parser:      bodyParserAdapter.New(cspReportToBodyParser),
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				ctx := request.Context()

				reports, err := muxUtils.GetParsedRequestBody[[]*reporting_api.Report[*content_security_policy.CSPViolationReportBody]](ctx)
				if err != nil {
					return nil, &response_error.ResponseError{
						ServerError: fmt.Errorf("get parsed request body: %w", err),
					}
				}

				httpContext, err := utils.GetNonZeroContextValue[*motmedelHttpTypes.HttpContext](
					ctx,
					motmedelMux.MuxHttpContextContextKey,
				)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithError(
							request.Context(),
							fmt.Errorf("get non-zero context value: %w", err),
						),
						"An error occurred when retrieving the mux http context.",
					)
				}

				var message string
				if len(reports) == 1 {
					if report := reports[0]; report != nil {
						if reportBody := report.Body; reportBody != nil {
							message = reportBody.Message()
						}
					}

					// TODO: Maybe not good.
					if message == "" {
						message = "A CSP violation was reported."
					}
				} else {
					message = "Multiple CSP violations were reported."
				}

				httpReporting := httpContext.Reporting
				if httpReporting == nil {
					httpContext.Reporting = &schema.HttpReporting{}
					httpReporting = httpContext.Reporting
				}

				httpReporting.CspViolations = reports

				slog.WarnContext(
					motmedelHttpContext.WithHttpContextValue(ctx, httpContext),
					message,
					slog.Group(
						"event",
						slog.String("reason", "CSP violations were reported."),
						slog.String("action", "log_csp_violations"),
					),
				)

				return nil, nil
			},
		},
		&endpointPkg.Endpoint{
			Public: true,
			Path:   CspReportUriEndpoint,
			Method: http.MethodPost,
			BodyLoader: &body_loader.Loader{
				ContentType: "application/csp-report",
				MaxBytes:    8192,
				Parser:      bodyParserAdapter.New(cspReportUriBodyParser),
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				ctx := request.Context()

				report, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*content_security_policy.ReportEnvelope](ctx)
				if responseError != nil {
					return nil, responseError
				}

				httpContext, err := utils.GetNonZeroContextValue[*motmedelHttpTypes.HttpContext](
					ctx,
					motmedelMux.MuxHttpContextContextKey,
				)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithError(
							request.Context(),
							fmt.Errorf("get non-zero context value: %w", err),
						),
						"An error occurred when retrieving the mux http content.",
					)
				}

				httpReporting := httpContext.Reporting
				if httpReporting == nil {
					httpContext.Reporting = &schema.HttpReporting{}
					httpReporting = httpContext.Reporting
				}

				httpReporting.CspReport = report

				slog.WarnContext(
					motmedelHttpContext.WithHttpContextValue(ctx, httpContext),
					report.Message(),
					slog.Group(
						"event",
						slog.String("reason", "A CSP violation was reported."),
						slog.String("action", "log_csp_report"),
					),
				)

				return nil, nil
			},
		},
		&endpointPkg.Endpoint{
			Public: true,
			Path:   NetworkErrorLoggingEndpoint,
			Method: http.MethodPost,
			// TODO: Add body parsing.
			BodyLoader: &body_loader.Loader{
				ContentType: "application/reports+json",
				MaxBytes:    8192,
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				ctx := request.Context()

				httpContext, err := utils.GetNonZeroContextValue[*motmedelHttpTypes.HttpContext](
					ctx,
					motmedelMux.MuxHttpContextContextKey,
				)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithError(
							request.Context(),
							fmt.Errorf("get non-zero context value: %w", err),
						),
						"An error occurred when retrieving the mux http content.",
					)
				}

				slog.WarnContext(
					motmedelHttpContext.WithHttpContextValue(ctx, httpContext),
					"A network error was reported.",
				)

				return nil, nil
			},
		},
		&endpointPkg.Endpoint{
			Public: true,
			Path:   IntegrityEndpoint,
			Method: http.MethodPost,
			BodyLoader: &body_loader.Loader{
				ContentType: "application/reports+json",
				MaxBytes:    8192,
				Parser:      bodyParserAdapter.New(integrityPolicyBodyParser),
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				ctx := request.Context()

				reports, err := muxUtils.GetParsedRequestBody[[]*reporting_api.Report[*integrity_policy.IntegrityViolationReportBody]](ctx)
				if err != nil {
					return nil, &response_error.ResponseError{
						ServerError: fmt.Errorf("get parsed request body: %w", err),
					}
				}

				httpContext, err := utils.GetNonZeroContextValue[*motmedelHttpTypes.HttpContext](
					ctx,
					motmedelMux.MuxHttpContextContextKey,
				)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithError(
							request.Context(),
							fmt.Errorf("get non-zero context value: %w", err),
						),
						"An error occurred when retrieving the mux http context.",
					)
				}

				httpReporting := httpContext.Reporting
				if httpReporting == nil {
					httpContext.Reporting = &schema.HttpReporting{}
					httpReporting = httpContext.Reporting
				}

				httpReporting.IntegrityViolations = reports

				var message string
				if len(reports) == 1 {
					if report := reports[0]; report != nil {
						if reportBody := report.Body; reportBody != nil {
							message = reportBody.Message()
						}
					}

					// TODO: Maybe not good.
					if message == "" {
						message = "An integrity violation was reported."
					}
				} else {
					message = "Multiple integrity violations were reported."
				}

				slog.WarnContext(
					motmedelHttpContext.WithHttpContextValue(ctx, httpContext),
					message,
					slog.Group(
						"event",
						slog.String("reason", "Integrity violations were reported."),
						slog.String("action", "log_integrity_violations"),
					),
				)

				return nil, nil
			},
		},
		&endpointPkg.Endpoint{
			Public: true,
			Path:   "/api/report/error",
			Method: http.MethodPost,
			BodyLoader: &body_loader.Loader{
				ContentType: "application/json",
				MaxBytes:    8192,
				Parser:      bodyParserAdapter.New(errorBodyParser),
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				ctx := request.Context()

				body, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*js_error_report.ErrorBody](ctx)
				if responseError != nil {
					return nil, responseError
				}

				httpContext, err := utils.GetNonZeroContextValue[*motmedelHttpTypes.HttpContext](
					ctx,
					motmedelMux.MuxHttpContextContextKey,
				)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithError(
							request.Context(),
							fmt.Errorf("get non-zero context value: %w", err),
						),
						"An error occurred when retrieving the mux http context.",
					)
				}

				schemaError := &schema.Error{
					Type: body.Type,
				}
				if errorDetails := body.Error; errorDetails != nil {
					schemaError.Message = errorDetails.Message
					schemaError.StackTrace = errorDetails.Stack
					if errorDetails.Code != 0 {
						schemaError.Code = strconv.Itoa(errorDetails.Code)
					}
				}

				message := body.Message
				if message == "" {
					message = "A JavaScript error was reported."
				}

				errorMap, err := motmedelJson.ObjectToMap(schemaError)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithError(
							request.Context(),
							fmt.Errorf("object to map: %w", err),
						),
						"An error occurred when converting the schema error to a map.",
					)
				}

				slog.WarnContext(
					motmedelHttpContext.WithHttpContextValue(ctx, httpContext),
					message,
					slog.Group("error", motmedelLog.AttrsFromMap(errorMap)...),
					slog.Group(
						"event",
						slog.String("reason", "A JavaScript error was reported."),
						slog.String("action", "log_js_error"),
					),
				)

				return nil, nil
			},
		},
		&endpointPkg.Endpoint{
			Public: true,
			Path:   "/api/report/unhandled-rejection",
			Method: http.MethodPost,
			BodyLoader: &body_loader.Loader{
				ContentType: "application/json",
				MaxBytes:    8192,
				Parser:      bodyParserAdapter.New(unhandledRejectionBodyParser),
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				ctx := request.Context()

				body, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*js_error_report.BaseErrorBody](ctx)
				if responseError != nil {
					return nil, responseError
				}

				httpContext, err := utils.GetNonZeroContextValue[*motmedelHttpTypes.HttpContext](
					ctx,
					motmedelMux.MuxHttpContextContextKey,
				)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithError(
							request.Context(),
							fmt.Errorf("get non-zero context value: %w", err),
						),
						"An error occurred when retrieving the mux http context.",
					)
				}

				schemaError := &schema.Error{
					Type: body.Type,
				}
				message := "A JavaScript unhandled rejection was reported."
				if errorDetails := body.Error; errorDetails != nil {
					schemaError.Message = errorDetails.Message
					schemaError.StackTrace = errorDetails.Stack
					if errorDetails.Code != 0 {
						schemaError.Code = strconv.Itoa(errorDetails.Code)
					}
					if errorDetails.Message != "" {
						message = errorDetails.Message
					}
				}

				errorMap, err := motmedelJson.ObjectToMap(schemaError)
				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithError(
							request.Context(),
							fmt.Errorf("object to map: %w", err),
						),
						"An error occurred when converting the schema error to a map.",
					)
				}

				slog.WarnContext(
					motmedelHttpContext.WithHttpContextValue(ctx, httpContext),
					message,
					slog.Group("error", motmedelLog.AttrsFromMap(errorMap)...),
					slog.Group(
						"event",
						slog.String("reason", "A JavaScript unhandled rejection was reported."),
						slog.String("action", "log_js_unhandled_rejection"),
					),
				)

				return nil, nil
			},
		},
	)

	return nil
}

func PatchSecurityTxt(mux *motmedelMux.Mux, baseUrl *url.URL) error {
	if mux == nil {
		return nil
	}

	if baseUrl == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("base url"))
	}

	hostname := baseUrl.Hostname()
	var registeredDomain string
	if strings.EqualFold(hostname, "localhost") {
		registeredDomain = "localhost"
	} else {
		domainParts := domain_parts.New(hostname)
		if domainParts == nil {
			return motmedelErrors.NewWithTrace(nil_error.New("domain parts"))
		}
		registeredDomain = domainParts.RegisteredDomain
	}

	if !strings.EqualFold(hostname, registeredDomain) {
		registeredBaseUrl := &url.URL{Scheme: baseUrl.Scheme, Host: registeredDomain}
		if err := PatchOtherDomainSecurityTxt(mux, registeredBaseUrl.JoinPath("/.well-known/security.txt")); err != nil {
			return fmt.Errorf("patch other domain security txt: %w", err)
		}
		return nil
	}

	nowUtc := time.Now().UTC()
	data := []byte(
		fmt.Sprintf(
			"Contact: mailto:security@%s\nPreferred-Languages: sv, en\nCanonical: %s\nExpires: %s\n",
			registeredDomain,
			baseUrl.JoinPath("/.well-known/security.txt").String(),
			nowUtc.AddDate(1, 0, 0).Format("2006-01-02T15:04:05.000Z"),
		),
	)
	etag := motmedelHttpUtils.MakeStrongEtag(data)
	lastModified := nowUtc.Format("Mon, 02 Jan 2006 15:04:05") + " GMT"

	mux.Add(
		&endpointPkg.Endpoint{
			Path:   "/security.txt",
			Method: http.MethodGet,
			Handler: func(request *http.Request, bytes []byte) (*response.Response, *response_error.ResponseError) {
				return &response.Response{
					StatusCode: http.StatusPermanentRedirect,
					Headers:    []*response.HeaderEntry{{Name: "Location", Value: "/.well-known/security.txt"}},
				}, nil
			},
			Public: true,
		},
		&endpointPkg.Endpoint{
			Path:   "/.well-known/security.txt",
			Method: http.MethodGet,
			StaticContent: &static_content.StaticContent{
				StaticContentData: static_content.StaticContentData{
					Data:         data,
					Etag:         etag,
					LastModified: lastModified,
					Headers: muxUtils.MakeStaticContentHeaders(
						"text/plain",
						"no-cache",
						etag,
						lastModified,
					),
				},
			},
			Public: true,
		},
	)

	return nil
}

func PatchFedCm(mux *motmedelMux.Mux, manifestUrls []*url.URL, providerUrls []*url.URL) error {
	if mux == nil {
		return nil
	}

	if len(providerUrls) == 0 {
		return nil
	}

	defaultDocumentHeaders := mux.DefaultDocumentHeaders
	if defaultDocumentHeaders == nil {
		// TODO: Create error in mux errors
		return motmedelErrors.NewWithTrace(errors.New("nil default document headers"))
	}

	csp, err := mux.GetContentSecurityPolicy()
	if err != nil {
		return fmt.Errorf("mux get content security policy: %w", err)
	}
	if csp == nil {
		csp, err = contentSecurityPolicyParsing.Parse([]byte(response_writer.DefaultContentSecurityPolicyString))
		if err != nil {
			return fmt.Errorf("parse content security policy: %w", err)
		}
	}
	if csp == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("content security policy"))
	}

	cspUtils.PatchCspConnectSrcWithHostSrc(csp, providerUrls...)
	if err := mux.SetContentSecurityPolicy(csp); err != nil {
		return fmt.Errorf("mux set content security policy: %w", err)
	}

	var permissionPolicyEntries []string
	for _, providerUrl := range providerUrls {
		if providerUrl == nil {
			continue
		}

		permissionPolicyEntries = append(
			permissionPolicyEntries,
			fmt.Sprintf("identity-credentials-get=(self \"%s\")", providerUrl.String()),
		)
	}

	permissionsPolicy := defaultDocumentHeaders[PermissionsPolicyHeader]
	if permissionsPolicy != "" {
		permissionsPolicy += ", "
	}
	permissionsPolicy += strings.Join(permissionPolicyEntries, ", ")
	defaultDocumentHeaders[PermissionsPolicyHeader] = permissionsPolicy

	return nil
}

func PatchOtherDomainSecurityTxt(mux *motmedelMux.Mux, securityTxtUrl *url.URL) error {
	if mux == nil {
		return nil
	}

	if securityTxtUrl == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("security txt url"))
	}

	urlString := securityTxtUrl.String()

	mux.Add(
		&endpointPkg.Endpoint{
			Path:   "/security.txt",
			Method: http.MethodGet,
			Handler: func(request *http.Request, bytes []byte) (*response.Response, *response_error.ResponseError) {
				return &response.Response{
					StatusCode: http.StatusPermanentRedirect,
					Headers:    []*response.HeaderEntry{{Name: "Location", Value: urlString}},
				}, nil
			},
			Public: true,
		},
		&endpointPkg.Endpoint{
			Path:   "/.well-known/security.txt",
			Method: http.MethodGet,
			Handler: func(request *http.Request, bytes []byte) (*response.Response, *response_error.ResponseError) {
				return &response.Response{
					StatusCode: http.StatusPermanentRedirect,
					Headers:    []*response.HeaderEntry{{Name: "Location", Value: urlString}},
				}, nil
			},
			Public: true,
		},
	)

	return nil
}

func PatchTrustedTypes(mux *motmedelMux.Mux, policies ...string) error {
	if mux == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("mux"))
	}

	if len(policies) == 0 {
		return nil
	}

	defaultDocumentHeaders := mux.DefaultDocumentHeaders
	if defaultDocumentHeaders == nil {
		// TODO: Create error in mux errors
		return motmedelErrors.NewWithTrace(errors.New("nil default document headers"))
	}

	requireTrustedTypesForDirective := &content_security_policy.RequireTrustedTypesForDirective{
		SinkGroups: []string{"script"},
	}

	var expressions []content_security_policy.TrustedTypeExpression
	for _, policy := range policies {
		if policy == "" {
			continue
		}

		expressions = append(
			expressions,
			content_security_policy.TrustedTypeExpression{
				Kind:  "policy-name",
				Value: policy,
			},
		)
	}
	if len(expressions) == 0 {
		return nil
	}

	trustedTypesDirective := &content_security_policy.TrustedTypesDirective{Expressions: expressions}

	var contentSecurityPolicy *content_security_policy.ContentSecurityPolicy
	if contentSecurityPolicyString := defaultDocumentHeaders[ContentSecurityPolicyHeader]; contentSecurityPolicyString != "" {
		var err error
		contentSecurityPolicy, err = contentSecurityPolicyParsing.Parse(
			[]byte(contentSecurityPolicyString),
		)
		if err != nil {
			return motmedelErrors.New(
				fmt.Errorf("parse content security policy: %w", err),
				contentSecurityPolicyString,
			)
		}

		if _, found := contentSecurityPolicy.GetDirective("require-trusted-types-for"); !found {
			contentSecurityPolicy.Directives = append(contentSecurityPolicy.Directives, requireTrustedTypesForDirective)
		}

		if existingTrustedTypesDirective := contentSecurityPolicy.GetTrustedTypes(); existingTrustedTypesDirective != nil {
			expressionsMap := make(map[string]struct{})
			for _, expression := range existingTrustedTypesDirective.Expressions {
				if expression.Kind == "policy-name" {
					expressionsMap[expression.Value] = struct{}{}
				}
			}

			for _, expression := range trustedTypesDirective.Expressions {
				if _, found := expressionsMap[expression.Value]; !found {
					existingTrustedTypesDirective.Expressions = append(
						existingTrustedTypesDirective.Expressions,
						content_security_policy.TrustedTypeExpression{
							Kind:  expression.Kind,
							Value: expression.Value,
						},
					)
				}
			}
		} else {
			contentSecurityPolicy.Directives = append(contentSecurityPolicy.Directives, trustedTypesDirective)
		}
	} else {
		contentSecurityPolicy = &content_security_policy.ContentSecurityPolicy{
			Directives: []content_security_policy.DirectiveI{
				requireTrustedTypesForDirective,
				trustedTypesDirective,
			},
		}
	}

	defaultDocumentHeaders[ContentSecurityPolicyHeader] = contentSecurityPolicy.String()

	return nil
}

func PatchHttpServiceMux(mux *motmedelMux.Mux, baseUrl *url.URL) error {
	if mux == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("mux"))
	}

	if baseUrl == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("base url"))
	}

	if err := PatchErrorReporting(mux, baseUrl); err != nil {
		return fmt.Errorf("patch error reporting: %w", err)
	}

	if hostname := baseUrl.Hostname(); hostname != "localhost" {
		if err := PatchStrictTransportSecurity(mux); err != nil {
			return fmt.Errorf("patch strict transport security: %w", err)
		}
	}

	return nil
}

func PatchPublicHttpServiceMux(mux *motmedelMux.Mux, baseUrl *url.URL) error {
	if mux == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("mux"))
	}

	if baseUrl == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("base url"))
	}

	if err := PatchHttpServiceMux(mux, baseUrl); err != nil {
		return fmt.Errorf("patch http service mux: %w", err)
	}

	if err := PatchCrawlable(mux, baseUrl, mux.GetDocumentEndpointSpecifications()); err != nil {
		return fmt.Errorf("patch crawlable: %w", err)
	}

	if err := PatchSecurityTxt(mux, baseUrl); err != nil {
		return fmt.Errorf("patch security txt: %w", err)
	}

	PatchMuxProblemDetailConverter(mux)

	return nil
}
