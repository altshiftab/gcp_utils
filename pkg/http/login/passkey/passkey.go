package passkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	motmedelCrypto "github.com/Motmedel/utils_go/pkg/crypto"
	motmedelEcdsa "github.com/Motmedel/utils_go/pkg/crypto/ecdsa"
	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelRsa "github.com/Motmedel/utils_go/pkg/crypto/rsa"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux"
	bodyParserAdapter "github.com/Motmedel/utils_go/pkg/http/mux/interfaces/body_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/parsing"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	jsonSchemaBodyParser "github.com/Motmedel/utils_go/pkg/http/mux/utils/body_parser/json/schema"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	motmedelNetErrors "github.com/Motmedel/utils_go/pkg/net/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	passkeyProviderErrors "github.com/altshiftab/gcp_utils/pkg/http/login/passkey/errors"
	passkeyHelpers "github.com/altshiftab/gcp_utils/pkg/http/login/passkey/helpers"
	"github.com/altshiftab/gcp_utils/pkg/http/login/passkey/helpers/login"
	"github.com/altshiftab/gcp_utils/pkg/http/login/passkey/helpers/login/types"
	loginBodyInput "github.com/altshiftab/gcp_utils/pkg/http/login/passkey/helpers/login/types/body_input"
	"github.com/altshiftab/gcp_utils/pkg/http/login/passkey/helpers/registration"
	registrationBodyInput "github.com/altshiftab/gcp_utils/pkg/http/login/passkey/helpers/registration/types/body_input"
	passkeyUtilsErrors "github.com/altshiftab/passkey_utils/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_creation_options"
	transportUserEntity "github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_entity/public_key_credential_user_entity/transport"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
	passkeyUtilsValidation "github.com/altshiftab/passkey_utils/pkg/utils/validation"
)

type UserHandler interface {
	GetPublicKeyCredential(ctx context.Context, credentialId []byte) (*types.SigningData, error)
	AddPublicKeyCredential(ctx context.Context, userId string, credential *public_key_credential.AttestationPublicKeyCredential) error
	UpdatePublicKeyCredential(ctx context.Context, credentialId []byte, signatureCount uint32) error
	AddRegistrationIssuance(ctx context.Context, userId string, challenge []byte) error
	DeleteRegistrationIssuance(ctx context.Context, challenge []byte) (string, error)
	// TODO: Maybe this should return an error as well?
	GenerateUserId(ctx context.Context) string
	AddUser(ctx context.Context, userId string, emailAddress string) error
}

type SessionHandler interface {
	AddPublicKeyAuthenticationRequest(ctx context.Context, challenge []byte) error
	DeletePublicKeyAuthenticationRequest(ctx context.Context, challenge []byte) error
	HandleSuccessfulAuthentication(ctx context.Context, userId string) ([]*muxResponse.HeaderEntry, error)
}

func PatchMux(
	mux *mux.Mux,
	sessionHandler SessionHandler,
	userHandler UserHandler,
	originUrl *url.URL,
	relayingParty *public_key_credential_creation_options.RelayingParty,
	allowedCoseAlgorithms []int,
) error {
	if mux == nil {
		return nil
	}

	if originUrl == nil {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilOriginUrl)
	}

	originUrlString := originUrl.String()
	originUrlHostName := originUrl.Hostname()

	domainBreakdown := domain_breakdown.GetDomainBreakdown(originUrlHostName)
	if domainBreakdown == nil {
		return motmedelErrors.New(motmedelNetErrors.ErrNilDomainBreakdown)
	}

	if utils.IsNil(sessionHandler) {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilSessionHandler)
	}

	if utils.IsNil(userHandler) {
		return motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrNilUserHandler)
	}

	if relayingParty == nil {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrNilRelayingParty)
	}

	relayingPartyId := relayingParty.Id
	if relayingPartyId == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyRelayingPartyId)
	}

	relayingPartyName := relayingParty.Name
	if relayingPartyName == "" {
		return motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyRelayingPartyName)
	}

	loginPublicKeyCredentialBodyParser, err := jsonSchemaBodyParser.NewWithProcessor(loginBodyInput.PublicKeyCredentialProcessor)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("json schema body parser new with processor (login public key credential): %w", err))
	}

	registerPublicKeyCredentialBodyParser, err := jsonSchemaBodyParser.NewWithProcessor(registrationBodyInput.PublicKeyCredentialProcessor)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("json schema body parser new with processor (register public key credential): %w", err))
	}

	mux.Add(
		&endpoint_specification.EndpointSpecification{
			Path:   "/api/login/passkey/options",
			Method: http.MethodGet,
			Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				challenge, err := passkeyHelpers.GenerateChallenge()
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("generate challenge: %w", err)),
					}
				}

				if err := sessionHandler.AddPublicKeyAuthenticationRequest(ctx, challenge); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("login add challenge to database: %w", err),
							challenge,
						),
					}
				}

				optionsBytes, err := login.MakeOptionsBytes(challenge, relayingPartyId)
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("login make options bytes: %w", err),
							challenge,
						),
					}
				}

				return &muxResponse.Response{
					Headers: []*muxResponse.HeaderEntry{{Name: "Content-Type", Value: "application/json"}},
					Body:    optionsBytes,
				}, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   "/api/login/passkey",
			Method: http.MethodPost,
			BodyParserConfiguration: &parsing.BodyParserConfiguration{
				ContentType: "application/json",
				MaxBytes:    2048,
				Parser:      bodyParserAdapter.New(loginPublicKeyCredentialBodyParser),
			},
			Handler: func(request *http.Request, requestBody []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				bodyInput, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*loginBodyInput.BodyInput](ctx)
				if responseError != nil {
					return nil, responseError
				}

				credentialId := bodyInput.CredentialId
				if len(credentialId) == 0 {
					return nil, &muxResponseError.ResponseError{
						ClientError: motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyCredentialId),
						ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
							http.StatusUnprocessableEntity,
							"The credential id is empty.",
							nil,
						),
					}
				}

				// NOTE: The user is identified solely based on the credential ID, no email address e.g.
				signingData, err := userHandler.GetPublicKeyCredential(ctx, credentialId)
				if err != nil {
					wrappedErr := fmt.Errorf("get database signing data: %w", err)

					if errors.Is(err, passkeyProviderErrors.ErrNoPublicKeyCredential) {
						return nil, &muxResponseError.ResponseError{
							ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
								"No stored public key credential was found for the given credential id.",
								nil,
							),
							ClientError: wrappedErr,
						}
					} else {
						return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
					}
				}
				if signingData == nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(passkeyProviderErrors.ErrNilSigningData),
					}
				}

				challenge := bodyInput.Challenge
				if err := sessionHandler.DeletePublicKeyAuthenticationRequest(ctx, challenge); err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("session handler delete public key authentication request: %w", err),
						sessionHandler, challenge,
					)

					if responseError := passkeyHelpers.MakeDatabaseChallengeResponseError(wrappedErr); responseError != nil {
						return nil, responseError
					} else {
						return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
					}
				}

				publicKeyData := signingData.PublicKey
				publicKey, err := x509.ParsePKIXPublicKey(publicKeyData)
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("x509 parse pkix public key: %w", err),
							publicKeyData,
						),
					}
				}

				var verifier motmedelCryptoInterfaces.Verifier

				switch typedPublicKey := publicKey.(type) {
				case *ecdsa.PublicKey:
					ecdsaMethod, err := motmedelEcdsa.FromPublicKey(typedPublicKey)
					if err != nil {
						return nil, &muxResponseError.ResponseError{
							ServerError: motmedelErrors.NewWithTrace(
								fmt.Errorf("ecdsa from public key: %w", err),
								publicKey,
							),
						}
					}
					verifier = &motmedelEcdsa.Asn1DerEncodedMethod{Method: *ecdsaMethod}
				case *rsa.PublicKey:
					coseAlgorithm := signingData.PublicKeyAlgorithm
					name, ok := motmedelCrypto.CoseAlgNames[coseAlgorithm]
					if !ok {
						return nil, &muxResponseError.ResponseError{
							ServerError: motmedelErrors.NewWithTrace(
								passkeyProviderErrors.ErrUnexpectedAlgorithm,
								coseAlgorithm,
							),
						}
					}

					rsaMethod, err := motmedelRsa.New(name, nil, typedPublicKey)
					if err != nil {
						return nil, &muxResponseError.ResponseError{
							ServerError: motmedelErrors.NewWithTrace(
								fmt.Errorf("rsa new: %w", err),
								typedPublicKey,
							),
						}
					}

					verifier = rsaMethod
				default:
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(motmedelErrors.ErrConversionNotOk, publicKey),
					}
				}

				err = passkeyUtilsValidation.ValidateAssertionPublicKeyCredential(
					bodyInput.Credential,
					bodyInput.RawClientDataJson,
					bodyInput.RawAuthenticatorData,
					challenge,
					originUrlString,
					relayingPartyId,
					signingData.SignatureCount,
					verifier,
				)
				if err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("validate ecdsa assertion public key credential: %w", err),
						bodyInput.Credential,
						bodyInput.RawClientDataJson,
						bodyInput.RawAuthenticatorData,
						challenge,
						originUrlString,
						relayingPartyId,
						signingData.SignatureCount,
						verifier,
					)

					if errors.Is(err, motmedelErrors.ErrValidationError) {
						validationResponseError := passkeyHelpers.MakeValidationResponseError(
							wrappedErr,
							passkeyUtilsValidation.AssertionBadRequestErrors,
						)
						if validationResponseError == nil {
							return nil, &muxResponseError.ResponseError{
								ServerError: motmedelErrors.New(passkeyProviderErrors.ErrNilValidationResponseError),
							}
						}
						return nil, validationResponseError
					}

					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}

				signatureCount := signingData.SignatureCount
				if err := userHandler.UpdatePublicKeyCredential(ctx, credentialId, signatureCount); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("update public key credential: %w", err),
							credentialId, signatureCount,
						),
					}
				}

				userId := bodyInput.UserId
				headerEntries, err := sessionHandler.HandleSuccessfulAuthentication(ctx, userId)
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("session handler handle successful authentication: %w", err),
							sessionHandler, userId,
						),
					}
				}

				return &muxResponse.Response{Headers: headerEntries}, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   "/api/register/passkey/options",
			Method: http.MethodGet,
			Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				challenge, err := passkeyHelpers.GenerateChallenge()
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("generate challenge: %w", err)),
					}
				}

				userId := userHandler.GenerateUserId(ctx)
				transportUserId := transport.Base64URL(userId)

				// NOTE: `Name` and `DisplayName` are set client side.
				optionsBytes, err := registration.MakeRegistrationOptionsBytes(
					&transportUserEntity.PublicKeyCredentialUserEntity{
						Id: &transportUserId,
					},
					relayingParty,
					challenge,
					allowedCoseAlgorithms,
				)
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("make registration options bytes: %w", err),
						),
					}
				}

				if err := userHandler.AddRegistrationIssuance(ctx, userId, challenge); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("user handler add token issuance: %w", err),
							userHandler, userId, challenge,
						),
					}
				}

				return &muxResponse.Response{
					Headers: []*muxResponse.HeaderEntry{{Name: "Content-Type", Value: "application/json"}},
					Body:    optionsBytes,
				}, nil
			},
		},
		&endpoint_specification.EndpointSpecification{
			Path:   "/api/register/passkey",
			Method: http.MethodPost,
			BodyParserConfiguration: &parsing.BodyParserConfiguration{
				ContentType: "application/json",
				Parser:      bodyParserAdapter.New(registerPublicKeyCredentialBodyParser),
				MaxBytes:    2048,
			},
			Handler: func(request *http.Request, requestBody []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				bodyInput, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*registrationBodyInput.BodyInput](ctx)
				if responseError != nil {
					return nil, responseError
				}

				challenge := bodyInput.Credential.Response.ClientDataJson.Challenge
				userId, err := userHandler.DeleteRegistrationIssuance(ctx, challenge)
				if err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("user handler delete token issuance: %w", err),
						userHandler,
					)

					if responseError := passkeyHelpers.MakeDatabaseChallengeResponseError(wrappedErr); responseError != nil {
						return nil, responseError
					} else {
						return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
					}
				}

				err = passkeyUtilsValidation.ValidateAttestationPublicKeyCredential(
					bodyInput.Credential,
					challenge,
					originUrlString,
					relayingPartyId,
					allowedCoseAlgorithms,
				)
				if err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("validate attestation public key credential: %w", err),
						bodyInput.Credential, challenge, originUrlString, relayingPartyId, allowedCoseAlgorithms,
					)

					if errors.Is(err, motmedelErrors.ErrValidationError) {
						validationResponseError := passkeyHelpers.MakeValidationResponseError(
							wrappedErr,
							passkeyUtilsValidation.AttestationBadRequestErrors,
						)
						if validationResponseError == nil {
							return nil, &muxResponseError.ResponseError{
								ServerError: motmedelErrors.New(passkeyProviderErrors.ErrNilValidationResponseError),
							}
						}
						return nil, validationResponseError
					}

					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}

				if err := userHandler.AddUser(ctx, userId, ""); err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("user handler add user: %w", err),
						userHandler, userId,
					)

					if errors.Is(err, passkeyProviderErrors.ErrEmailAddressUserIdConflict) {
						return nil, &muxResponseError.ResponseError{
							ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
								http.StatusConflict,
								"The email address is already registered with a different user id.",
								nil,
							),
							ClientError: wrappedErr,
						}
					}

					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}

				credential := bodyInput.Credential
				if err := userHandler.AddPublicKeyCredential(ctx, userId, credential); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("user handler add public key credential: %w", err),
							userHandler, userId, credential,
						),
					}
				}

				return nil, nil
			},
		},
	)

	return nil
}
