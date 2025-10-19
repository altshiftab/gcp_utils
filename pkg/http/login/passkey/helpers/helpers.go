package helpers

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	altshiftGcpUtilsHttpLoginErrors "github.com/altshiftab/gcp_utils/pkg/http/login/errors"
	passkeyUtilsValidation "github.com/altshiftab/passkey_utils/pkg/utils/validation"
)

func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 64)
	if _, err := rand.Read(challenge); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return challenge, nil
}

func MakeValidationResponseError(err error, badRequestErrors []error) *muxResponseError.ResponseError {
	var statusCode int
	isBadRequestErr := motmedelErrors.IsAny(err, passkeyUtilsValidation.CommonBadRequestErrors...) || motmedelErrors.IsAny(err, badRequestErrors...)
	if isBadRequestErr {
		statusCode = http.StatusBadRequest
	} else {
		statusCode = http.StatusUnprocessableEntity
	}

	return &muxResponseError.ResponseError{
		ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
			statusCode,
			"The public key credential did not pass validation.",
			nil,
		),
		ClientError: err,
	}
}

func MakeDatabaseChallengeResponseError(err error) *muxResponseError.ResponseError {
	if errors.Is(err, altshiftGcpUtilsHttpLoginErrors.ErrNoChallenge) {
		return &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.MakeBadRequestProblemDetail(
				"No challenge was found.",
				nil,
			),
			ClientError: err,
		}
	} else if errors.Is(err, altshiftGcpUtilsHttpLoginErrors.ErrExpiredChallenge) {
		return &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
				http.StatusUnauthorized,
				"The challenge has expired.",
				nil,
			),
			ClientError: err,
		}
	} else {
		return nil
	}
}
