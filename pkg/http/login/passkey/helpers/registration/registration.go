package registration

import (
	"encoding/json"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	passkeyUtilsError "github.com/altshiftab/passkey_utils/pkg/errors"
	"github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_creation_options"
	transportCreateOptions "github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_creation_options/transport"
	transportUserEntity "github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_entity/public_key_credential_user_entity/transport"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

func MakeRegistrationOptionsBytes(
	user *transportUserEntity.PublicKeyCredentialUserEntity,
	relayingParty *public_key_credential_creation_options.RelayingParty,
	challenge []byte,
	allowedCoseAlgorithms []int,
) ([]byte, error) {
	if user == nil {
		return nil, motmedelErrors.NewWithTrace(passkeyUtilsError.ErrNilUserEntity)
	}

	if relayingParty == nil {
		return nil, motmedelErrors.NewWithTrace(passkeyUtilsError.ErrNilRelayingParty)
	}

	if len(challenge) == 0 {
		return nil, motmedelErrors.NewWithTrace(passkeyUtilsError.ErrEmptyChallenge)
	}

	if len(allowedCoseAlgorithms) == 0 {
		return nil, motmedelErrors.NewWithTrace(altshiftGcpUtilsHttpLoginErrors.ErrEmptyAllowedAlgs)
	}

	var publickeyCredentialParams []*public_key_credential_creation_options.PublicKeyCredentialParam
	for _, coseAlgorithm := range allowedCoseAlgorithms {
		publickeyCredentialParams = append(
			publickeyCredentialParams,
			&public_key_credential_creation_options.PublicKeyCredentialParam{
				Type: "public-key",
				Alg:  coseAlgorithm,
			},
		)
	}

	transportChallenge := transport.Base64URL(challenge)

	options := transportCreateOptions.PublicKeyCredentialCreationOptions{
		RelyingParty:     relayingParty,
		User:             user,
		Challenge:        &transportChallenge,
		PubKeyCredParams: publickeyCredentialParams,
		AuthenticatorSelection: &public_key_credential_creation_options.AuthenticatorSelection{
			AuthenticatorAttachment: "platform",
			ResidentKeyPreference:   "required",
			RequireResidentKey:      true,
		},
		Attestation: "none",
	}

	optionsBytes, err := json.Marshal(options)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), options)
	}

	return optionsBytes, nil
}
