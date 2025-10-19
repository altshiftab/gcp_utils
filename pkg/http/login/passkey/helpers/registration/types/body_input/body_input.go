package body_input

import (
	"net/http"

	"github.com/Motmedel/utils_go/pkg/http/mux/interfaces/body_processor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	passkeyUtilsErrors "github.com/altshiftab/passkey_utils/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential/transport"
)

type BodyInput struct {
	Credential *public_key_credential.AttestationPublicKeyCredential
}

var PublicKeyCredentialProcessor = body_processor.BodyProcessorFunction[*BodyInput, *transport.AttestationPublicKeyCredential](
	func(transportCredential *transport.AttestationPublicKeyCredential) (*BodyInput, *response_error.ResponseError) {
		credential, err := transport.MakeAttestationPublicKeyCredential(transportCredential)
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
				ServerError: passkeyUtilsErrors.ErrNilPublicKeyCredential,
			}
		}

		return &BodyInput{Credential: credential}, nil
	},
)
