package session_response_processor

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	motmedelCryptoErrors "github.com/Motmedel/utils_go/pkg/crypto/errors"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	"github.com/Motmedel/utils_go/pkg/interfaces/comparer"
	motmedelJwkErrors "github.com/Motmedel/utils_go/pkg/json/jose/jwk/errors"
	motmedelJwkKey "github.com/Motmedel/utils_go/pkg/json/jose/jwk/types/key"
	motmedelJwtErrors "github.com/Motmedel/utils_go/pkg/json/jose/jwt/errors"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticate_config"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/header_validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/setting"
	motmedelMaps "github.com/Motmedel/utils_go/pkg/maps"
	motmedelTimeErrors "github.com/Motmedel/utils_go/pkg/time/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	gcpUtilsLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	dbscErrors "github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/errors"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/session_response_processor/session_response_processor_config"
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
	Audience       string
	CheckChallenge func(ctx context.Context, challenge string, authenticationId string) (userId string, err error)
	config         *session_response_processor_config.Config
}

func (p *Processor) Process(ctx context.Context, input *Input) (*Output, *response_error.ResponseError) {
	if input == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(dbscErrors.ErrNilInput)}
	}

	tokenString := input.TokenString
	if tokenString == "" {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(dbscErrors.ErrEmptyTokenString)}
	}

	authenticationId := input.AuthenticationId
	if authenticationId == "" {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(dbscErrors.ErrEmptyAuthenticationId)}
	}

	token, err := motmedelJwtToken.New(tokenString)
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("new token: %w", err), tokenString)
		if errors.Is(err, motmedelErrors.ErrParseError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
					"Invalid token.",
					nil,
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if token == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(motmedelJwtErrors.ErrNilToken)}
	}

	tokenPayload := token.Payload
	if tokenPayload == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(motmedelJwtErrors.ErrNilTokenPayload)}
	}

	key, err := motmedelMaps.MapGetConvert[map[string]any](tokenPayload, "key")
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("map get convert: %w", err), tokenPayload)
		if motmedelErrors.IsAny(err, motmedelErrors.ErrConversionNotOk, motmedelErrors.ErrNotInMap) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
					"Invalid token; no key object.",
					nil,
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if key == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(motmedelErrors.ErrNilMap),
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				"Invalid token; nil key object.",
				nil,
			),
		}
	}

	jwkKey, err := motmedelJwkKey.New(key)
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("jwk key new: %w", err), key)
		if errors.Is(err, motmedelErrors.ErrValidationError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
					"Invalid token; bad key object.",
					err,
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if jwkKey == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(motmedelJwkErrors.ErrNilKey)}
	}

	namedVerifier, err := jwkKey.NamedVerifier()
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("jwk key named verifier: %w", err), key)
		if errors.Is(err, motmedelJwkErrors.ErrEmptyAlg) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
					"Invalid token; empty or missing alg in key.",
					err,
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if utils.IsNil(namedVerifier) {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(motmedelCryptoErrors.ErrNilVerifier)}
	}

	derEncodedKeyMateral, err := x509.MarshalPKIXPublicKey(jwkKey.Material)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(
				fmt.Errorf("%w: x509 marshal pkix public key: %w", motmedelErrors.ErrValidationError, err),
				key,
			),
		}
	}

	var userId string

	_, err = motmedelJwtToken.Authenticate(
		tokenString,
		authenticate_config.WithTokenValidator(
			&validator.Validator{
				HeaderValidator: &header_validator.Validator{
					Settings: map[string]setting.Setting{
						"alg": setting.Required,
						"typ": setting.Required,
					},
					Expected: &header_validator.ExpectedFields{
						Alg: comparer.NewEqualComparer(p.config.Algs...),
						Typ: comparer.NewEqualComparer("dbsc+jwt"),
					},
				},
				PayloadValidator: &registered_claims_validator.RegisteredClaimsValidator{
					Settings: map[string]setting.Setting{
						"aud": setting.Required,
						"iat": setting.Required,
						"jti": setting.Required,
						"key": setting.Required,
					},
					Expected: &registered_claims_validator.ExpectedRegisteredClaims{
						AudienceComparer: comparer.NewEqualComparer(p.Audience),
						IdComparer: comparer.Function[string](
							func(jtiChallenge string) (bool, error) {
								var err error
								userId, err = p.CheckChallenge(ctx, jtiChallenge, authenticationId)
								if err != nil {
									if motmedelErrors.IsAny(err, gcpUtilsLoginErrors.ErrEmptyChallenge, motmedelTimeErrors.ErrExpired) {
										return false, nil
									}

									return false, motmedelErrors.New(
										fmt.Errorf("session handler delete dbsc challenge: %w", err),
										jtiChallenge, authenticationId,
									)
								}

								return true, nil
							},
						),
					},
				},
			},
		),
	)

	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("jwt authenticate: %w", err), tokenString, authenticationId)
		if motmedelErrors.IsAny(wrappedErr, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError, motmedelErrors.ErrParseError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
					"Invalid token.",
					nil,
				),
			}
		}

		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}

	return &Output{PublicKey: derEncodedKeyMateral, UserId: userId}, nil
}

func New(
	audience string,
	checkChallenge func(ctx context.Context, challenge string, authenticationId string) (userId string, err error),
	options ...session_response_processor_config.Option,
) (*Processor, error) {
	if audience == "" {
		return nil, motmedelErrors.NewWithTrace(dbscErrors.ErrEmptyAudience)
	}

	if checkChallenge == nil {
		return nil, motmedelErrors.NewWithTrace(dbscErrors.ErrNilCheckChallenge)
	}

	return &Processor{Audience: audience, CheckChallenge: checkChallenge, config: session_response_processor_config.New(options...)}, nil
}
