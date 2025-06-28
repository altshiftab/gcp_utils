package http

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	motmedelEnv "github.com/Motmedel/utils_go/pkg/env"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelMux "github.com/Motmedel/utils_go/pkg/http/mux"
	motmedelMuxErrors "github.com/Motmedel/utils_go/pkg/http/mux/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	muxTypesEndpointSpecification "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/parsing"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_writer"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/static_content"
	"github.com/Motmedel/utils_go/pkg/http/mux/utils/generate"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelHttpTypesSitemapxml "github.com/Motmedel/utils_go/pkg/http/types/sitemapxml"
	motmedelHttpUtils "github.com/Motmedel/utils_go/pkg/http/utils"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	motmedelNetErrors "github.com/Motmedel/utils_go/pkg/net/errors"
	motmedelGcpUtilsEnv "github.com/altshiftab/gcp_utils/pkg/env"
	altshiftabGcpUtilsHttpErrors "github.com/altshiftab/gcp_utils/pkg/http/errors"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DomainVariableName = "DOMAIN"

const (
	PermissionsPolicyHeader = "Permissions-Policy"
	ContentSecurityPolicyHeader = "Content-Security-Policy"
)

func PatchMuxProblemDetailConverter(mux *motmedelMux.Mux) {
	if mux == nil {
		return
	}

	mux.ProblemDetailConverter = response_error.ProblemDetailConverterFunction(
		func(detail *problem_detail.ProblemDetail, negotiation *motmedelHttpTypes.ContentNegotiation) ([]byte, string, error) {
			data, contentType, err := response_error.ConvertProblemDetail(detail, negotiation)
			if contentType == "application/problem+xml" {
				contentType = "application/xml"
			}
			return data, contentType, err
		},
	)
}

func PatchMux(mux *motmedelMux.Mux) {
	if mux == nil {
		return
	}

	PatchMuxProblemDetailConverter(mux)

	if motmedelGcpUtilsEnv.GetLogLevelWithDefault() == "DEBUG" {
		mux.DoneCallback = func(ctx context.Context) {
			slog.DebugContext(ctx, "An HTTP response was served.")
		}
	}
}

func makeSitemapXmlUrl(
	staticContentData *static_content.StaticContentData,
	location string,
) (*motmedelHttpTypesSitemapxml.Url, error) {
	if staticContentData == nil {
		return nil, nil
	}

	if location == "" {
		return nil, motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrEmptyLocation)
	}

	var lastModified string
	var isDocument bool
	for _, header := range staticContentData.Headers {
		switch strings.ToLower(header.Name) {
		case "content-type":
			isDocument = true
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
	specifications []*endpoint_specification.EndpointSpecification,
) error {
	if mux == nil {
		return nil
	}

	if baseUrl == nil {
		return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilBaseUrl)
	}

	nowUtc := time.Now().UTC()

	var sitemapXmlUrls []*motmedelHttpTypesSitemapxml.Url

	for _, specification := range specifications {
		staticContent := specification.StaticContent
		if staticContent == nil {
			continue
		}

		path := specification.Path
		pathUrl := baseUrl.JoinPath(path)
		if pathUrl == nil {
			return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilPathUrl, path)
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
			return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilSitemapXmlUrl, baseUrl)
		}

		mux.Add(
			&endpoint_specification.EndpointSpecification{
				Path:   "/sitemap.xml",
				Method: http.MethodGet,
				StaticContent: &static_content.StaticContent{
					StaticContentData: static_content.StaticContentData{
						Data:         sitemapXmlData,
						Etag:         sitemapXmlEtag,
						LastModified: sitemapXmlLastModified,
						Headers: generate.MakeStaticContentHeaders(
							"application/xml",
							"no-cache",
							sitemapXmlEtag,
							sitemapXmlLastModified,
						),
					},
				},
			},
		)

		otherRecords = [][2]string{{"Sitemap", sitemapXmlUrl.String()}}
	}

	mux.Add(
		generate.MakeRobotsTxt(
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
		return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilDefaultHeaders)
	}

	defaultHeaders["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

	return nil
}

func PatchErrorReporting(mux *motmedelMux.Mux, baseUrl *url.URL) error {
	if mux == nil {
		return nil
	}

	if baseUrl == nil {
		return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilBaseUrl)
	}

	defaultHeaders := mux.DefaultHeaders
	if defaultHeaders == nil {
		return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilDefaultHeaders)
	}

	defaultDocumentHeaders := mux.DefaultDocumentHeaders
	if defaultDocumentHeaders == nil {
		return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilDefaultDocumentHeaders)
	}

	defaultHeaders["Report-To"] = fmt.Sprintf(
		"{\"group\": \"network-error-logging\", \"max-age\": 10886400, \"endpoints\": [{\"url\": \"%s/api/report/network-error-logging\"}]}",
		baseUrl.String(),
	)
	defaultHeaders["NEL"] = `{"report_to": "network-error-logging", "max_age": 10886400}`
	defaultDocumentHeaders["Reporting-Endpoints"] = `csp-report-to="/api/report/csp-report-to"`

	contentSecurityPolicy := defaultDocumentHeaders[ContentSecurityPolicyHeader]
	if contentSecurityPolicy != "" {
		contentSecurityPolicy += "; "
	}
	contentSecurityPolicy += "report-to csp-report-to; report-uri /api/report/csp-report-uri"

	defaultDocumentHeaders[ContentSecurityPolicyHeader] = contentSecurityPolicy

	mux.Add(
		// TODO: Not sure about the content type.
		&endpoint_specification.EndpointSpecification{
			Path:   "/api/report/csp-report-to",
			Method: http.MethodPost,
			// TODO: Add body parsing.
			BodyParserConfiguration: &parsing.BodyParserConfiguration{
				ContentType: "application/reports+json",
				MaxBytes:    8192,
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				slog.Default().WarnContext(request.Context(), "A Content-Security-Report was received.")
				return nil, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   "/api/report/csp-report-uri",
			Method: http.MethodPost,
			// TODO: Add body parsing.
			BodyParserConfiguration: &parsing.BodyParserConfiguration{
				ContentType: "application/reports+json",
				MaxBytes:    8192,
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				slog.Default().WarnContext(request.Context(), "A Content-Security-Report was received.")
				return nil, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   "/api/report/error",
			Method: http.MethodPost,
			// TODO: Add body parsing.
			BodyParserConfiguration: &parsing.BodyParserConfiguration{
				ContentType: "application/json",
				MaxBytes:    8192,
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				slog.Default().WarnContext(request.Context(), "A JavaScript error was reported.")
				return nil, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   "/api/report/unhandled-rejection",
			Method: http.MethodPost,
			// TODO: Add body parsing.
			BodyParserConfiguration: &parsing.BodyParserConfiguration{
				ContentType: "application/json",
				MaxBytes:    8192,
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				slog.Default().WarnContext(request.Context(), "An JavaScript unhandled rejection was reported.")
				return nil, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   "/api/report/network-error-logging",
			Method: http.MethodPost,
			// TODO: Add body parsing.
			BodyParserConfiguration: &parsing.BodyParserConfiguration{
				ContentType: "application/reports+json",
				MaxBytes:    8192,
			},
			Handler: func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
				slog.Default().WarnContext(request.Context(), "Network errors were reported.")
				return nil, nil
			},
		},
	)

	return nil
}

func PatchSecurityTxt(mux *motmedelMux.Mux, data []byte) {
	if mux == nil {
		return
	}

	nowUtc := time.Now().UTC()
	etag := motmedelHttpUtils.MakeStrongEtag(data)
	lastModified := nowUtc.Format("Mon, 02 Jan 2006 15:04:05") + " GMT"

	mux.Add(
		&endpoint_specification.EndpointSpecification{
			Path:   "/security.txt",
			Method: http.MethodGet,
			Handler: func(request *http.Request, bytes []byte) (*response.Response, *response_error.ResponseError) {
				return &response.Response{
					StatusCode: http.StatusPermanentRedirect,
					Headers:    []*response.HeaderEntry{{Name: "Location", Value: "/.well-known/security.txt"}},
				}, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   "/.well-known/security.txt",
			Method: http.MethodGet,
			StaticContent: &static_content.StaticContent{
				StaticContentData: static_content.StaticContentData{
					Data:         data,
					Etag:         etag,
					LastModified: lastModified,
					Headers: generate.MakeStaticContentHeaders(
						"text/plain",
						"no-cache",
						etag,
						lastModified,
					),
				},
			},
		},
	)
}

func PatchFedCm(mux *motmedelMux.Mux, providerUrls ...string) error {
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

	var permissionPolicyEntries []string
	for _, providerUrl := range providerUrls {
		if providerUrl == "" {
			continue
		}

		permissionPolicyEntries = append(
			permissionPolicyEntries,
			fmt.Sprintf("identity-credentials-get=(self \"%s\")", providerUrl),
		)
	}

	permissionsPolicy := defaultDocumentHeaders[PermissionsPolicyHeader]
	if permissionsPolicy != "" {
		permissionsPolicy += " "
	}
	permissionsPolicy += strings.Join(permissionPolicyEntries, " ")
	defaultDocumentHeaders[PermissionsPolicyHeader] = permissionsPolicy

	return nil
}

func PatchOtherDomainSecurityTxt(mux *motmedelMux.Mux, securityTxtUrl *url.URL) error {
	if mux == nil {
		return nil
	}

	if securityTxtUrl == nil {
		return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilSecurityTxtUrl)
	}

	urlString := securityTxtUrl.String()

	mux.Add(
		&endpoint_specification.EndpointSpecification{
			Path:   "/security.txt",
			Method: http.MethodGet,
			Handler: func(request *http.Request, bytes []byte) (*response.Response, *response_error.ResponseError) {
				return &response.Response{
					StatusCode: http.StatusPermanentRedirect,
					Headers:    []*response.HeaderEntry{{Name: "Location", Value: urlString}},
				}, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   "/.well-known/security.txt",
			Method: http.MethodGet,
			Handler: func(request *http.Request, bytes []byte) (*response.Response, *response_error.ResponseError) {
				return &response.Response{
					StatusCode: http.StatusPermanentRedirect,
					Headers:    []*response.HeaderEntry{{Name: "Location", Value: urlString}},
				}, nil
			},
		},
	)

	return nil
}

func MakeMux(
	specifications []*muxTypesEndpointSpecification.EndpointSpecification,
	contextKeyValuePairs [][2]any,
) *motmedelMux.Mux {
	mux := &motmedelMux.Mux{}
	mux.DefaultHeaders = maps.Clone(response_writer.DefaultHeaders)
	mux.DefaultDocumentHeaders = maps.Clone(response_writer.DefaultDocumentHeaders)
	mux.SetContextKeyValuePairs = contextKeyValuePairs
	mux.Add(specifications...)

	PatchMux(mux)

	return mux
}

func PatchHttpServiceMux(mux *motmedelMux.Mux, baseUrl *url.URL) error {
	if mux == nil {
		return motmedelErrors.NewWithTrace(motmedelMuxErrors.ErrNilMux)
	}

	if baseUrl == nil {
		// TODO: Create error in utils go url errors
		return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilBaseUrl)
	}

	defaultDocumentHeaders := mux.DefaultDocumentHeaders
	if defaultDocumentHeaders == nil {
		// TODO: Create error in mux errors
		return motmedelErrors.NewWithTrace(errors.New("nil default document headers"))
	}

	contentSecurityPolicy := defaultDocumentHeaders["Content-Security-Policy"]
	if contentSecurityPolicy != "" {
		contentSecurityPolicy += "; "
	}
	contentSecurityPolicy += "require-trusted-types-for 'script'; trusted-types lit-html"
	defaultDocumentHeaders["Content-Security-Policy"] = contentSecurityPolicy

	if err := PatchErrorReporting(mux, baseUrl); err != nil {
		return motmedelErrors.New(fmt.Errorf("patch error reporting: %w", err), mux, baseUrl)
	}

	if err := PatchStrictTransportSecurity(mux); err != nil {
		return motmedelErrors.New(fmt.Errorf("patch strict transport security: %w", err), mux)
	}

	return nil
}

func PatchPublicHttpServiceMux(mux *motmedelMux.Mux, baseUrl *url.URL) error {
	if mux == nil {
		return motmedelErrors.NewWithTrace(motmedelMuxErrors.ErrNilMux)
	}

	if baseUrl == nil {
		return motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilBaseUrl)
	}

	if err := PatchHttpServiceMux(mux, baseUrl); err != nil {
		return fmt.Errorf("patch http service mux: %w", err)
	}

	documentEndpointSpecifications := mux.GetDocumentEndpointSpecifications()

	if err := PatchCrawlable(mux, baseUrl, documentEndpointSpecifications); err != nil {
		return fmt.Errorf("patch crawlable: %w", err)
	}

	domainBreakdown := domain_breakdown.GetDomainBreakdown(baseUrl.Hostname())
	if domainBreakdown == nil {
		return motmedelErrors.NewWithTrace(motmedelNetErrors.ErrNilDomainBreakdown)
	}

	registeredDomain := domainBreakdown.RegisteredDomain

	registeredDomainUrlString := fmt.Sprintf("https://www.%s", registeredDomain)
	registeredDomainUrl, err := url.Parse(registeredDomainUrlString)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("url parse: %w", err), registeredDomainUrlString)
	}
	securityTxtUrl := registeredDomainUrl.JoinPath("/.well-known/security.txt")

	if domainBreakdown.Subdomain == "" {
		PatchSecurityTxt(
			mux,
			[]byte(
				fmt.Sprintf(
					"Contact: mailto:security@%s\nPreferred-Languages: sv, en\nCanonical: %s\nExpires: %s\n",
					registeredDomain,
					securityTxtUrl.String(),
					time.Now().UTC().AddDate(1, 0, 0).Format("2006-01-02T15:04:05.000Z"),
				),
			),
		)
	} else {
		if err := PatchOtherDomainSecurityTxt(mux, securityTxtUrl); err != nil {
			return motmedelErrors.New(fmt.Errorf("patch other domain security txt: %w", err), securityTxtUrl)
		}
	}

	mux.ProblemDetailConverter = response_error.ProblemDetailConverterFunction(
		func(detail *problem_detail.ProblemDetail, negotiation *motmedelHttpTypes.ContentNegotiation) ([]byte, string, error) {
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

	return nil
}

func makeHttpService(
	staticContentEndpointSpecifications []*muxTypesEndpointSpecification.EndpointSpecification,
	public bool,
	redirects ...[2]string,
) (*http.Server, *motmedelMux.Mux, error) {
	port := motmedelEnv.GetEnvWithDefault("PORT", "8080")
	domain, err := motmedelEnv.ReadEnv(DomainVariableName)
	if err != nil {
		return nil, nil, motmedelErrors.New(fmt.Errorf("read env: %q", err), DomainVariableName)
	}

	mux := MakeMux(staticContentEndpointSpecifications, nil)
	if mux == nil {
		return nil, nil, motmedelErrors.NewWithTrace(motmedelMuxErrors.ErrNilMux)
	}

	baseUrl, err := url.Parse(fmt.Sprintf("https://%s", domain))
	if err != nil {
		return nil, nil, motmedelErrors.New(fmt.Errorf("url parse: %w", err), domain)
	}
	if baseUrl == nil {
		return nil, nil, motmedelErrors.NewWithTrace(altshiftabGcpUtilsHttpErrors.ErrNilBaseUrl)
	}

	if public {
		if err := PatchPublicHttpServiceMux(mux, baseUrl); err != nil {
			return nil, nil, motmedelErrors.New(fmt.Errorf("patch public http service mux: %w", err), mux)
		}
	} else {
		if err := PatchHttpServiceMux(mux, baseUrl); err != nil {
			return nil, nil, motmedelErrors.New(fmt.Errorf("patch http service mux: %w", err), mux)
		}
	}

	hostToSpecification := map[string]*motmedelMux.VhostMuxSpecification{domain: {Mux: mux}}

	for _, redirect := range redirects {
		hostToSpecification[redirect[0]] = &motmedelMux.VhostMuxSpecification{RedirectTo: redirect[1]}
	}

	vhostMux := &motmedelMux.VhostMux{HostToSpecification: hostToSpecification}
	vhostMux.DefaultHeaders = mux.DefaultHeaders

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           h2c.NewHandler(vhostMux, &http2.Server{}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	return httpServer, mux, nil
}

func MakePublicHttpService(
	staticContentEndpointSpecifications []*muxTypesEndpointSpecification.EndpointSpecification,
	redirects ...[2]string,
) (*http.Server, *motmedelMux.Mux, error) {
	return makeHttpService(staticContentEndpointSpecifications, true, redirects...)
}

func MakeHttpService(
	staticContentEndpointSpecifications []*muxTypesEndpointSpecification.EndpointSpecification,
	redirects ...[2]string,
) (*http.Server, *motmedelMux.Mux, error) {
	return makeHttpService(staticContentEndpointSpecifications, false, redirects...)
}
