package http_context_extractor

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpContext "github.com/Motmedel/utils_go/pkg/http/context"
	"github.com/Motmedel/utils_go/pkg/http/parsing/headers/authorization"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelJson "github.com/Motmedel/utils_go/pkg/json"
	"github.com/Motmedel/utils_go/pkg/json/jose/jws"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaUtils "github.com/Motmedel/utils_go/pkg/schema/utils"
)

const maskedValue = "(MASKED)"

func maskJws(serialization string) string {
	if parts, err := jws.Split(serialization); err == nil {
		parts[2] = maskedValue
		return strings.Join(parts[:], jws.Delimiter)
	}
	return maskedValue
}

func maskSetCookieHeader(setCookieHeader string) string {
	header := http.Header{}
	header.Add("Set-Cookie", setCookieHeader)
	resp := &http.Response{Header: header}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return setCookieHeader
	}

	// Replace only the cookie value, reconstruct with original attributes
	c := cookies[0]
	c.Value = maskJws(c.Value)

	return c.String()
}

func maskCookieHeader(cookieHeader string) string {
	header := http.Header{}
	header.Add("Cookie", cookieHeader)
	req := &http.Request{Header: header}

	cookies := req.Cookies()
	masked := make([]string, len(cookies))
	for i, c := range cookies {
		masked[i] = c.Name + "=" + maskJws(c.Value)
	}
	return strings.Join(masked, "; ")
}

func maskBasicAuth(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return maskedValue
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return maskedValue
	}

	return base64.StdEncoding.EncodeToString([]byte(parts[0]+":")) + maskedValue
}

func extractNormalizedHeaders(header http.Header) string {
	var headerStrings []string

	for name, values := range header {
		for _, value := range values {
			if name == "Set-Cookie" {
				value = maskSetCookieHeader(value)
			} else if name == "Authorization" {
				parsedValue, err := authorization.Parse([]byte(value))
				if err == nil && parsedValue != nil {
					for k := range parsedValue.Params {
						parsedValue.Params[k] = maskedValue
					}

					if strings.ToLower(parsedValue.Scheme) == "basic" {
						parsedValue.Token68 = maskBasicAuth(parsedValue.Token68)
					} else {
						parsedValue.Token68 = maskJws(parsedValue.Token68)
					}

					value = parsedValue.String()
				} else {
					value = maskedValue
				}
			} else if name == "Cookie" {
				value = maskCookieHeader(value)
			} else if name == "X-Goog-Iap-Jwt-Assertion" {
				value = maskJws(value)
			}

			headerStrings = append(headerStrings, fmt.Sprintf("%s: %s\r\n", name, value))
		}
	}

	return strings.Join(headerStrings, "")
}

type Extractor struct {
}

func (e *Extractor) Handle(ctx context.Context, record *slog.Record) error {
	if record == nil {
		return nil
	}

	if requestId, ok := ctx.Value(motmedelHttpContext.RequestIdContextKey).(string); ok {
		record.Add(slog.Group("http", slog.Group("request", slog.String("id", requestId))))
	}

	if httpContext, ok := ctx.Value(motmedelHttpContext.HttpContextContextKey).(*motmedelHttpTypes.HttpContext); ok && httpContext != nil {
		base, err := schemaUtils.ParseHttpContext(httpContext)
		if err != nil {
			return motmedelErrors.New(fmt.Errorf("parse http context: %w", err), httpContext)
		}

		if base != nil {
			if request := httpContext.Request; request != nil {
				if requestHeader := request.Header; requestHeader != nil {
					if base.Http == nil {
						base.Http = &schema.Http{}
					}

					if base.Http.Request == nil {
						base.Http.Request = &schema.HttpRequest{}
					}

					// NOTE: Potential nil pointer dereference
					base.Http.Request.HttpHeaders = &schema.HttpHeaders{
						Normalized: extractNormalizedHeaders(requestHeader),
					}
				}
			}

			if response := httpContext.Response; response != nil {
				if responseHeader := response.Header; responseHeader != nil {
					if base.Http == nil {
						base.Http = &schema.Http{}
					}

					if base.Http.Response == nil {
						base.Http.Response = &schema.HttpResponse{}
					}

					// NOTE: Potential nil pointer dereference
					base.Http.Response.HttpHeaders = &schema.HttpHeaders{
						Normalized: extractNormalizedHeaders(responseHeader),
					}
				}
			}

			baseMap, err := motmedelJson.ObjectToMap(base)
			if err != nil {
				return motmedelErrors.New(fmt.Errorf("object to map: %w", err), base)
			}

			record.Add(motmedelLog.AttrsFromMap(baseMap)...)

			if baseMessage := base.Message; baseMessage != "" {
				record.Message = baseMessage
			}
		}
	}

	return nil
}

func New() *Extractor {
	return &Extractor{}
}
