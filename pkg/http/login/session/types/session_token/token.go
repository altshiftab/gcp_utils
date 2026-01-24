package session_token

import (
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"time"

	motmedelCryptoErrors "github.com/Motmedel/utils_go/pkg/crypto/errors"
	"github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/Motmedel/utils_go/pkg/utils"
	errors2 "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	"github.com/google/uuid"
)

type Token struct {
	*registered_claims.Claims
	SubjectId           string
	SubjectEmailAddress string
	TenantId            string
	TenantName          string
	Roles               []string
}

func (token *Token) GetUser() *motmedelHttpTypes.HttpContextUser {
	user := &motmedelHttpTypes.HttpContextUser{
		Id:    token.SubjectId,
		Email: token.SubjectEmailAddress,
	}

	if token.TenantId != "" || token.TenantName != "" {
		user.Group = &motmedelHttpTypes.HttpContextGroup{
			Id:   token.TenantId,
			Name: token.TenantName,
		}
	}

	user.Roles = token.Roles

	return user
}

func (token *Token) UserAttributes() []any {
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

func NewEncodedToken(
	authenticationId string,
	userId string,
	userEmail string,
	signer interfaces.NamedSigner,
	expiresAt time.Time,
	issuer string,
	customClaims map[string]any,
) (string, error) {
	if authenticationId == "" {
		return "", motmedelHttpErrors.NewWithTrace(errors2.ErrEmptyAuthenticationId)
	}

	if userId == "" {
		return "", motmedelHttpErrors.NewWithTrace(errors2.ErrEmptyUserId)
	}

	if utils.IsNil(signer) {
		return "", motmedelHttpErrors.NewWithTrace(motmedelCryptoErrors.ErrNilSigner)
	}

	if issuer == "" {
		return "", motmedelHttpErrors.NewWithTrace(errors2.ErrEmptyIssuer)
	}

	payload := map[string]any{
		"jti": strings.Join([]string{authenticationId, uuid.New().String()}, ":"),
		"sub": strings.Join([]string{userId, userEmail}, ":"),
		"exp": expiresAt.Unix(),
		"nbf": time.Now().Unix(),
		"iss": issuer,
	}
	maps.Copy(payload, customClaims)

	token := motmedelJwtToken.Token{Payload: payload}

	tokenString, err := token.Encode(signer)
	if err != nil {
		return "", motmedelHttpErrors.New(fmt.Errorf("token encode: %w", err), token, signer)
	}

	return tokenString, nil
}
