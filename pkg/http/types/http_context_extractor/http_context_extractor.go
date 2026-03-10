package http_context_extractor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpContext "github.com/Motmedel/utils_go/pkg/http/context"
	"github.com/Motmedel/utils_go/pkg/http/parsing/headers/authorization"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelJson "github.com/Motmedel/utils_go/pkg/json"
	"github.com/Motmedel/utils_go/pkg/json/jose/jws"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaUtils "github.com/Motmedel/utils_go/pkg/schema/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/types/http_context_extractor/http_context_extractor_config"
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

func extractJwtStrings(header http.Header) []string {
	var candidates []string

	if authHeader := header.Get("Authorization"); authHeader != "" {
		if scheme, token, found := strings.Cut(authHeader, " "); found && strings.EqualFold(scheme, "bearer") && token != "" {
			candidates = append(candidates, token)
		}
	}

	for _, cookie := range (&http.Request{Header: header}).Cookies() {
		if cookie.Value != "" {
			candidates = append(candidates, cookie.Value)
		}
	}

	return candidates
}

func decodeJwtPayload(token string) (map[string]any, error) {
	parts, err := jws.Split(token)
	if err != nil {
		return nil, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func userFromSessionClaims(claims *session_claims.Claims) *schema.User {
	sub := claims.Subject
	if sub == "" {
		return nil
	}

	subjectId, subjectEmailAddress, found := strings.Cut(sub, ":")
	if !found {
		return nil
	}

	user := &schema.User{
		Id:         subjectId,
		Email:      subjectEmailAddress,
		Unverified: true,
	}

	if azp := claims.AuthorizedParty; azp != "" {
		if tenantId, tenantName, found := strings.Cut(azp, ":"); found {
			if tenantId != "" || tenantName != "" {
				user.Group = &schema.Group{
					Id:   tenantId,
					Name: tenantName,
				}
			}
		}
	}

	user.Roles = claims.Roles

	return user
}

func userFromSubClaim(sub string) *schema.User {
	user := &schema.User{Unverified: true}

	if strings.Contains(sub, "@") {
		user.Email = sub
	} else {
		user.Name = sub
	}

	return user
}

func userFromBasicAuth(header http.Header) *schema.User {
	authHeader := header.Get("Authorization")
	if authHeader == "" {
		return nil
	}

	scheme, credentials, found := strings.Cut(authHeader, " ")
	if !found || !strings.EqualFold(scheme, "basic") || credentials == "" {
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(credentials)
	if err != nil {
		return nil
	}

	username, _, found := strings.Cut(string(decoded), ":")
	if !found || username == "" {
		return nil
	}

	user := &schema.User{Unverified: true}
	if strings.Contains(username, "@") {
		user.Email = username
	} else {
		user.Name = username
	}

	return user
}

func extractUnverifiedUser(header http.Header) *schema.User {
	for _, token := range extractJwtStrings(header) {
		claims, err := decodeJwtPayload(token)
		if err != nil {
			continue
		}

		if sessionClaims, err := session_claims.New(claims); err == nil && sessionClaims != nil {
			if user := userFromSessionClaims(sessionClaims); user != nil {
				return user
			}
		}

		if sub, ok := claims["sub"].(string); ok && sub != "" {
			return userFromSubClaim(sub)
		}
	}

	if user := userFromBasicAuth(header); user != nil {
		return user
	}

	return nil
}

func urlMatchesPattern(pattern *schema.Url, incoming *schema.Url) (bool, []string) {
	if pattern == nil || incoming == nil {
		return false, nil
	}

	if pattern.Domain != "" && pattern.Domain != incoming.Domain {
		return false, nil
	}
	if pattern.Path != "" && pattern.Path != incoming.Path {
		return false, nil
	}
	if pattern.RegisteredDomain != "" && pattern.RegisteredDomain != incoming.RegisteredDomain {
		return false, nil
	}
	if pattern.Subdomain != "" && pattern.Subdomain != incoming.Subdomain {
		return false, nil
	}
	if pattern.TopLevelDomain != "" && pattern.TopLevelDomain != incoming.TopLevelDomain {
		return false, nil
	}

	if pattern.Query == "" {
		return true, nil
	}

	patternQuery, err := url.ParseQuery(pattern.Query)
	if err != nil {
		return false, nil
	}

	incomingQuery, err := url.ParseQuery(incoming.Query)
	if err != nil {
		return false, nil
	}

	var paramsToMask []string
	for paramName := range patternQuery {
		if incomingQuery.Has(paramName) {
			paramsToMask = append(paramsToMask, paramName)
		}
	}

	return true, paramsToMask
}

func (e *Extractor) maskUrl(urlStruct *schema.Url) {
	if urlStruct == nil || len(e.MaskedUrlParams) == 0 {
		return
	}

	paramsToMask := make(map[string]struct{})
	for _, maskedUrlParam := range e.MaskedUrlParams {
		if matches, params := urlMatchesPattern(maskedUrlParam, urlStruct); matches {
			for _, param := range params {
				paramsToMask[param] = struct{}{}
			}
		}
	}

	if len(paramsToMask) == 0 {
		return
	}

	maskQueryParams := func(urlStr string) string {
		if urlStr == "" {
			return urlStr
		}

		parsedUrl, err := url.Parse(urlStr)
		if err != nil {
			return urlStr
		}

		queryValues := parsedUrl.Query()
		modified := false
		for param := range paramsToMask {
			if queryValues.Has(param) {
				queryValues.Set(param, maskedValue)
				modified = true
			}
		}

		if modified {
			parsedUrl.RawQuery = queryValues.Encode()
			return parsedUrl.String()
		}

		return urlStr
	}

	urlStruct.Full = maskQueryParams(urlStruct.Full)
	urlStruct.Original = maskQueryParams(urlStruct.Original)

	if urlStruct.Query != "" {
		parsedQuery, err := url.ParseQuery(urlStruct.Query)
		if err == nil {
			modified := false
			for param := range paramsToMask {
				if parsedQuery.Has(param) {
					parsedQuery.Set(param, maskedValue)
					modified = true
				}
			}
			if modified {
				urlStruct.Query = parsedQuery.Encode()
			}
		}
	}
}

type Extractor struct {
	ReplaceableMessages map[string]struct{}
	MaskedUrlParams     []*schema.Url
}

func (e *Extractor) Handle(ctx context.Context, record *slog.Record) error {
	if record == nil {
		return nil
	}

	if requestId, ok := ctx.Value(motmedelHttpContext.RequestIdContextKey).(string); ok {
		record.Add(slog.Group("http", slog.Group("request", slog.String("id", requestId))))
	}

	if httpContext, ok := ctx.Value(motmedelHttpContext.HttpContextContextKey).(*motmedelHttpTypes.HttpContext); ok && httpContext != nil {
		if httpContext.User == nil {
			if request := httpContext.Request; request != nil {
				if requestHeader := request.Header; requestHeader != nil {
					httpContext.User = extractUnverifiedUser(requestHeader)
				}
			}
		}

		base, err := schemaUtils.ParseHttpContext(httpContext)
		if err != nil {
			return motmedelErrors.New(fmt.Errorf("parse http context: %w", err), httpContext)
		}

		if base != nil {
			// Mask URL query parameters if configured
			if base.Url != nil {
				e.maskUrl(base.Url)
			}

			if request := httpContext.Request; request != nil {
				if requestHeader := request.Header; requestHeader != nil {
					if base.Http == nil {
						base.Http = &schema.Http{}
					}

					if base.Http.Request == nil {
						base.Http.Request = &schema.HttpRequest{}
					}

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

					base.Http.Response.HttpHeaders = &schema.HttpHeaders{
						Normalized: extractNormalizedHeaders(responseHeader),
					}
				}
			}

			if e.ReplaceableMessages != nil {
				if _, ok := e.ReplaceableMessages[record.Message]; ok {
					record.Message = base.Message
				}
			}
			base.Message = ""

			baseMap, err := motmedelJson.ObjectToMap(base)
			if err != nil {
				return motmedelErrors.New(fmt.Errorf("object to map: %w", err), base)
			}

			record.Add(motmedelLog.AttrsFromMap(baseMap)...)
		}
	}

	return nil
}

func New(options ...http_context_extractor_config.Option) *Extractor {
	config := http_context_extractor_config.New(options...)

	var messagesMap map[string]struct{}
	if len(config.ReplaceableMessages) > 0 {
		messagesMap = make(map[string]struct{}, len(config.ReplaceableMessages))
		for _, msg := range config.ReplaceableMessages {
			messagesMap[msg] = struct{}{}
		}
	}
	return &Extractor{
		ReplaceableMessages: messagesMap,
		MaskedUrlParams:     config.MaskedUrlParams,
	}
}
