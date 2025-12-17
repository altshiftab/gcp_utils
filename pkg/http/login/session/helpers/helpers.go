package helpers

import (
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"time"

	motmedelCryptoErrors "github.com/Motmedel/utils_go/pkg/crypto/errors"
	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	motmedelJwtErrors "github.com/Motmedel/utils_go/pkg/jwt/errors"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/jwt/types/token"
	"github.com/Motmedel/utils_go/pkg/utils"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types"
	"github.com/google/uuid"
)

func GenerateSessionId() string {
	return uuid.New().String()
}

func MakeSessionToken(
	authenticationId string,
	userId string,
	userEmail string,
	signer motmedelCryptoInterfaces.NamedSigner,
	expiresAt time.Time,
	issuer string,
	customClaims map[string]any,
) (string, error) {
	if authenticationId == "" {
		return "", motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptyAuthenticationId)
	}

	if userId == "" {
		return "", motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptyUserId)
	}

	if utils.IsNil(signer) {
		return "", motmedelErrors.NewWithTrace(motmedelCryptoErrors.ErrNilSigner)
	}

	if issuer == "" {
		return "", motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptyIssuer)
	}

	payload := map[string]any{
		"jti": strings.Join([]string{authenticationId, GenerateSessionId()}, ":"),
		"sub": strings.Join([]string{userId, userEmail}, ":"),
		"exp": expiresAt.Unix(),
		"nbf": time.Now().Unix(),
		"iss": issuer,
	}
	maps.Copy(payload, customClaims)

	token := motmedelJwtToken.Token{Payload: payload}

	tokenString, err := token.Encode(signer)
	if err != nil {
		return "", motmedelErrors.New(fmt.Errorf("token encode: %w", err), token, signer)
	}

	return tokenString, nil
}
func GetSessionCookieAttributes(domain string) string {
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

func MakeSessionCookie(
	tokenString string,
	expiresAt time.Time,
	name string,
	domain string,
) (*http.Cookie, error) {
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

func MakeSessionCookieHeader(
	authenticationId string,
	userId string,
	userEmail string,
	signer motmedelCryptoInterfaces.NamedSigner,
	cookieName string,
	expiresAt time.Time,
	issuer string,
	domain string,
	customClaims map[string]any,
) (*muxResponse.HeaderEntry, error) {
	if domain == "" {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptySessionCookieDomain)
	}

	sessionToken, err := MakeSessionToken(authenticationId, userId, userEmail, signer, expiresAt, issuer, customClaims)
	if err != nil {
		return nil, fmt.Errorf("make session token: %w", err)
	}

	sessionCookie, err := MakeSessionCookie(sessionToken, expiresAt, cookieName, domain)
	if err != nil {
		return nil, motmedelErrors.New(fmt.Errorf("make session cookie: %w", err), sessionToken)
	}
	if sessionCookie == nil {
		return nil, motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilCookie)
	}

	return &muxResponse.HeaderEntry{Name: "Set-Cookie", Value: sessionCookie.String()}, nil
}

func MakeUserAttrsFromJwtToken(token *types.JwtToken) []any {
	if token == nil {
		return nil
	}

	roles := token.Roles
	if len(roles) == 0 {
		roles = make([]string, 0)
	}

	attrs := []any{
		slog.String("id", token.SubjectId),
		slog.String("email", token.SubjectEmailAddress),
		slog.Any("roles", roles),
	}

	var groupAttrs []any

	if tenantId := token.TenantId; tenantId != "" {
		groupAttrs = append(groupAttrs, slog.String("id", tenantId))
	}

	if tenantName := token.TenantName; tenantName != "" {
		groupAttrs = append(groupAttrs, slog.String("name", tenantName))
	}

	if len(groupAttrs) > 0 {
		attrs = append(attrs, slog.Group("group", groupAttrs...))
	}

	return attrs
}
