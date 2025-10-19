package login

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	passkeyUtilsErrors "github.com/altshiftab/passkey_utils/pkg/errors"
	requestOptionsTransport "github.com/altshiftab/passkey_utils/pkg/types/public_key_credential_request_options/transport"
	"github.com/altshiftab/passkey_utils/pkg/utils/transport"
)

func MakeEcdsaPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("x509 parse pkix public key: %w", err))
	}

	ecdsaPublicKey, err := utils.Convert[*ecdsa.PublicKey](publicKey)
	if err != nil {
		return nil, motmedelErrors.New(fmt.Errorf("convert: %w", err), publicKey)
	}

	return ecdsaPublicKey, nil
}

func MakeOptionsBytes(challenge []byte, relayingPartyId string) ([]byte, error) {
	if len(challenge) == 0 {
		return nil, motmedelErrors.NewWithTrace(passkeyUtilsErrors.ErrEmptyChallenge)
	}

	transportChallenge := transport.Base64URL(challenge)

	// NOTE: Relaying party id is optional.
	options := requestOptionsTransport.PublicKeyCredentialRequestOptions{
		Challenge: &transportChallenge,
		RpId:      relayingPartyId,
	}

	optionsBytes, err := json.Marshal(options)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), options)
	}

	return optionsBytes, nil
}
