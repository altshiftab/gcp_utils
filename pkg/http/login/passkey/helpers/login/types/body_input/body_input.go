package body_input

import (
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/body_processor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	passkeyUtilsError "github.com/altshiftab/passkey_utils/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential/transport"
)

type BodyInput struct {
	Credential           *public_key_credential.AssertionPublicKeyCredential
	CredentialId         []byte
	Challenge            []byte
	UserId               string
	RawClientDataJson    []byte
	RawAuthenticatorData []byte
}

var PublicKeyCredentialProcessor = body_processor.BodyProcessorFunction[*BodyInput, *transport.AssertionPublicKeyCredential](
	func(transportCredential *transport.AssertionPublicKeyCredential) (*BodyInput, *response_error.ResponseError) {
		if transportCredential == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(passkeyUtilsError.ErrNilPublicKeyCredential),
			}
		}
		credential, err := transport.MakeAssertionPublicKeyCredential(transportCredential)
		if err != nil {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
					http.StatusUnprocessableEntity,
					"The public key credential could not be decoded.",
					nil,
				),
			}
		}
		if credential == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(passkeyUtilsError.ErrNilPublicKeyCredential),
			}
		}

		transportClientDataJson := transportCredential.Response.ClientDataJson
		if transportClientDataJson == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(passkeyUtilsError.ErrNilCollectedClientData),
			}
		}

		transportAuthenticatorData := transportCredential.Response.AuthenticatorData
		if transportAuthenticatorData == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(passkeyUtilsError.ErrNilAuthenticatorData),
			}
		}

		return &BodyInput{
			Credential:           credential,
			CredentialId:         credential.Id,
			Challenge:            credential.Response.ClientDataJson.Challenge,
			UserId:               string(credential.Response.UserHandle),
			RawClientDataJson:    *transportClientDataJson,
			RawAuthenticatorData: *transportAuthenticatorData,
		}, nil
	},
)
