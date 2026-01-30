package testing

import (
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	motmedelCryptoEddsa "github.com/Motmedel/utils_go/pkg/crypto/eddsa"
	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelSqlTesting "github.com/Motmedel/utils_go/pkg/database/sql/testing"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelHttpLog "github.com/Motmedel/utils_go/pkg/http/log"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/numeric_date"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelContextLogger "github.com/Motmedel/utils_go/pkg/log/context_logger"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_cookie"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
)

const (
	AuthenticationId = "test-authentication-id"
	Issuer           = "test-issuer"
	Audience         = "test-audience"
	SessionId        = "test-session-id"
	RegisteredDomain = "example.com"
)

func MakeCookieExplicit(
	authenticationId string,
	signer motmedelCryptoInterfaces.NamedSigner,
	authenticationMethods []string,
	exp, nbf time.Time,
) string {
	if utils.IsNil(signer) {
		panic(motmedelErrors.NewWithTrace(nil_error.New("signer")))
	}

	iat := time.Now()

	sessionClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Issuer:    Issuer,
			Subject:   "test-subject-id:test@example.com",
			Audience:  claim_strings.ClaimStrings{Audience},
			ExpiresAt: numeric_date.New(exp),
			NotBefore: numeric_date.New(nbf),
			IssuedAt:  numeric_date.New(iat),
			Id:        strings.Join([]string{authenticationId, SessionId}, ":"),
		},
		AuthenticationMethods: authenticationMethods,
		// NOTE: Not checked anywhere.
		AuthenticatedAt: numeric_date.New(iat.Add(-1 * 7 * 24 * time.Hour)),
		AuthorizedParty: "example.com:Test",
		Roles:           []string{"test-role"},
	}
	sessionToken, err := session_token.Parse(sessionClaims)
	if err != nil {
		panic(motmedelErrors.New(fmt.Errorf("session token parse: %w", err), sessionClaims))
	}
	if sessionToken == nil {
		panic(motmedelErrors.NewWithTrace(nil_error.New("session token")))
	}

	sessionTokenString, err := sessionToken.Encode(signer)
	if err != nil {
		panic(motmedelErrors.New(fmt.Errorf("new session token encode: %w", err), sessionToken, signer))
	}

	domain := "example.com"
	sessionCookie, err := session_cookie.New(sessionTokenString, exp, authorizer_request_parser_config.DefaultCookieName, domain)
	if err != nil {
		panic(motmedelErrors.New(fmt.Errorf("new session cookie: %w", err), sessionTokenString, exp, authorizer_request_parser_config.DefaultCookieName, domain))
	}

	return sessionCookie.String()
}

func MakeStandardCookie(authenticationId string, signer motmedelCryptoInterfaces.NamedSigner) string {
	now := time.Now()
	return MakeCookieExplicit(authenticationId, signer, []string{"ext"}, now.Add(1*time.Hour), now)
}

func SetUp() (*authorizer_request_parser.Parser, *motmedelCryptoEddsa.Method, *sql.DB) {
	httpContextExtractor := motmedelHttpLog.New()
	slog.SetDefault(
		motmedelContextLogger.New(
			slog.NewJSONHandler(
				os.Stdout,
				&slog.HandlerOptions{Level: slog.LevelInfo},
			),
			&motmedelLog.ErrorContextExtractor{
				ContextExtractors: []motmedelLog.ContextExtractor{
					httpContextExtractor,
				},
			},
			httpContextExtractor,
		),
	)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Errorf("ed25519 generate key: %w", err))
	}

	method := &motmedelCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}
	authorizerRequestParser, err := authorizer_request_parser.New(method, Issuer, Audience)
	if err != nil {
		panic(fmt.Errorf("authorizer request parser new: %w", err))
	}

	testDb := motmedelSqlTesting.NewDb()

	return authorizerRequestParser, method, testDb
}
