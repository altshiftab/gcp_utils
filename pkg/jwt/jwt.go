package jwt

import (
	"errors"
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
)

func Validate(claims jwt.Claims) error {
	registeredClaims, err := utils.GetNonZeroConversionValue[*jwt.RegisteredClaims](claims)
	if err != nil {
		return fmt.Errorf("get non zero conversion value: %w", err)
	}

	var errs []error

	err = jwt.NewValidator().Validate(claims)
	if err != nil {
		errs = append(errs, err)
	}

	if registeredClaims.ID == "" {
		errs = append(errs, fmt.Errorf("%w (jti)", jwt.ErrTokenRequiredClaimMissing))
	}

	if subject, _ := claims.GetSubject(); subject == "" {
		errs = append(errs, fmt.Errorf("%w (sub)", jwt.ErrTokenRequiredClaimMissing))
	}

	if expiresAt, _ := claims.GetExpirationTime(); expiresAt == nil {
		errs = append(errs, fmt.Errorf("%w (exp)", jwt.ErrTokenRequiredClaimMissing))
	}

	if notBefore, _ := claims.GetNotBefore(); notBefore == nil {
		errs = append(errs, fmt.Errorf("%w (nbf)", jwt.ErrTokenRequiredClaimMissing))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", motmedelErrors.ErrValidationError, errors.Join(errs...))
	}

	return nil
}
