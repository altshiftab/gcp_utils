package dbsc_session_response_processor

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	motmedelCryptoErrors "github.com/Motmedel/utils_go/pkg/crypto/errors"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/interfaces/comparer"
	motmedelJwkErrors "github.com/Motmedel/utils_go/pkg/json/jose/jwk/errors"
	motmedelJwkKey "github.com/Motmedel/utils_go/pkg/json/jose/jwk/types/key"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token/authenticated_token"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token/authenticated_token/authenticated_token_config"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/header_validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/setting"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/dbsc_challenge"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/dbsc_session_response_processor/dbsc_session_response_processor_config"
)

type Input struct {
	TokenString      string
	AuthenticationId string
	DbscSessionId    string
}

type Output struct {
	PublicKey []byte
	UserId    string
}

type Processor struct {
	TokenValidator *validator.Validator
	Db             *sql.DB

	popDbscChallenge func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error)
}

func (p *Processor) Process(ctx context.Context, input *Input) ([]byte, *response_error.ResponseError) {
	if input == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("input"))}
	}

	tokenString := input.TokenString
	if tokenString == "" {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(empty_error.New("token string"))}
	}

	authenticationId := input.AuthenticationId
	if authenticationId == "" {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication id"))}
	}

	token, err := motmedelJwtToken.New(tokenString)
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("new token: %w", err), tokenString)
		if errors.Is(err, motmedelErrors.ErrParseError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if token == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("jwt token"))}
	}

	tokenPayload := token.Payload
	if tokenPayload == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("jwt token payload"))}
	}

	key, err := utils.MapGetConvert[map[string]any](tokenPayload, "key")
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("map get convert: %w", err), tokenPayload)
		if motmedelErrors.IsAny(err, motmedelErrors.ErrConversionNotOk, motmedelErrors.ErrNotInMap) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token; no key object."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if key == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("token key object")),
			ProblemDetail: problem_detail.New(
				http.StatusBadRequest,
				problem_detail_config.WithDetail("Invalid token; nil key object."),
			),
		}
	}

	jwkKey, err := motmedelJwkKey.New(key)
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("jwk key new: %w", err), key)
		if errors.Is(err, motmedelErrors.ErrValidationError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token; bad key object."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if jwkKey == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("jwk key"))}
	}

	material := jwkKey.Material
	if utils.IsNil(material) {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("jwk key material"))}
	}

	namedVerifier, err := jwkKey.NamedVerifier()
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("jwk key named verifier: %w", err), key)
		if errors.Is(err, motmedelJwkErrors.ErrEmptyAlg) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token; empty or missing alg in key."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if utils.IsNil(namedVerifier) {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(motmedelCryptoErrors.ErrNilVerifier)}
	}

	publicKey, err := material.PublicKey()
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(
				fmt.Errorf("jwk key material public key: %w", err),
			),
		}
	}

	derEncodedKeyMaterial, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(
				fmt.Errorf("%w: x509 marshal pkix public key: %w", motmedelErrors.ErrValidationError, err),
				key,
			),
		}
	}
	if len(derEncodedKeyMaterial) == 0 {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("x509 marshal pkix public key material")),
		}
	}

	authenticatedToken, err := authenticated_token.New(
		tokenString,
		authenticated_token_config.WithTokenValidator(p.TokenValidator),
		authenticated_token_config.WithAllowUnauthenticated(true),
	)
	if err != nil {
		wrappedErr := motmedelErrors.New(
			fmt.Errorf("authenticated jwt token new: %w", err),
			tokenString, authenticationId,
		)
		if motmedelErrors.IsAny(wrappedErr, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError, motmedelErrors.ErrParseError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token."),
				),
			}
		}

		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if authenticatedToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authenticated jwt token")),
		}
	}

	authenticatedTokenPayload := authenticatedToken.Payload
	if authenticatedTokenPayload == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authenticated jwt token payload")),
		}
	}

	jti, err := utils.MapGetConvert[string](authenticatedTokenPayload, "jti")
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("map get convert (jti): %w", err), authenticatedTokenPayload),
		}
	}

	dbscChallenge, err := p.popDbscChallenge(ctx, jti, authenticationId, p.Db)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("get challenge: %w", err), jti, authenticationId),
		}
	}
	if dbscChallenge == nil {
		return nil, &response_error.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusBadRequest,
				problem_detail_config.WithDetail("No challenge was found matching the JTI and authentication ID."),
			),
		}
	}

	expiresAt := dbscChallenge.ExpiresAt
	if expiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("dbsc challenge expires at")),
		}
	}
	if time.Now().After(*expiresAt) {
		return nil, &response_error.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusBadRequest,
				problem_detail_config.WithDetail("The challenge has expired."),
			),
		}
	}

	return derEncodedKeyMaterial, nil
}

func New(audience string, db *sql.DB, options ...dbsc_session_response_processor_config.Option) (*Processor, error) {
	if audience == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("audience"))
	}

	if db == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("db"))
	}

	config := dbsc_session_response_processor_config.New(options...)

	tokenValidator := &validator.Validator{
		HeaderValidator: &header_validator.Validator{
			Settings: map[string]setting.Setting{
				"alg": setting.Required,
				"typ": setting.Required,
			},
			Expected: &header_validator.ExpectedFields{
				Alg: comparer.NewEqualComparer(config.Algs...),
				Typ: comparer.NewEqualComparer("dbsc+jwt"),
			},
		},
		PayloadValidator: &registered_claims_validator.Validator{
			Settings: map[string]setting.Setting{
				"aud": setting.Required,
				"iat": setting.Required,
				"jti": setting.Required,
				"key": setting.Required,
			},
			Expected: &registered_claims_validator.ExpectedClaims{
				AudienceComparer: comparer.NewEqualComparer(audience),
			},
		},
	}

	return &Processor{TokenValidator: tokenValidator, Db: db, popDbscChallenge: config.PopDbscChallenge}, nil
}
