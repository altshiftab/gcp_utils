package session_cookie

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelJwtErrors "github.com/Motmedel/utils_go/pkg/json/jose/jwt/errors"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
)

type SessionCookie = http.Cookie

func makeSessionCookie(value string, expiresAt time.Time, name string, domain string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		Expires:  expiresAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func New(tokenString string, expiresAt time.Time, name string, domain string) (*http.Cookie, error) {
	if tokenString == "" {
		return nil, motmedelErrors.NewWithTrace(motmedelJwtErrors.ErrEmptyTokenString)
	}

	if name == "" {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptySessionCookieName)
	}

	if domain == "" {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptySessionCookieDomain)
	}

	return makeSessionCookie(tokenString, expiresAt, name, domain), nil
}
func Attributes(domain string) string {
	c := makeSessionCookie("", time.Time{}, "", domain)
	if c == nil {
		return ""
	}

	var parts []string

	if len(c.Path) > 0 {
		parts = append(parts, "Path="+c.Path)
	}
	if len(c.Domain) > 0 {
		parts = append(parts, "Domain="+c.Domain)
	}
	if !c.Expires.IsZero() {
		parts = append(parts, "Expires="+c.Expires.UTC().Format(http.TimeFormat))
	}
	if c.MaxAge > 0 {
		parts = append(parts, fmt.Sprintf("Max-Age=%d", c.MaxAge))
	} else if c.MaxAge < 0 {
		parts = append(parts, "Max-Age=0")
	}
	if c.Secure {
		parts = append(parts, "Secure")
	}
	if c.HttpOnly {
		parts = append(parts, "HttpOnly")
	}
	switch c.SameSite {
	case http.SameSiteLaxMode:
		parts = append(parts, "SameSite=Lax")
	case http.SameSiteStrictMode:
		parts = append(parts, "SameSite=Strict")
	case http.SameSiteNoneMode:
		parts = append(parts, "SameSite=None")
	case http.SameSiteDefaultMode:
	}

	return strings.Join(parts, "; ")
}
