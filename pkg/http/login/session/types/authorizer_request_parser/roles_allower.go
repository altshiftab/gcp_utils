package authorizer_request_parser

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	motmedelJwtErrors "github.com/Motmedel/utils_go/pkg/json/jose/jwt/errors"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
)

type Parser struct {
	request_parser.RequestParser[*motmedelJwtToken.Token]

	AllowedRoles    []string
	AllowedTenantId string
	SuperAdminRoles []string
}

func (parser *Parser) Parse(request *http.Request) (*session_token.Token, *response_error.ResponseError) {
	jwtToken, responseError := parser.RequestParser.Parse(request)
	if responseError != nil {
		return nil, responseError
	}
	if jwtToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(motmedelJwtErrors.ErrNilToken),
		}
	}

	payload := jwtToken.Payload
	registeredClaims, err := registered_claims.New(payload)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("registered claims from map: %w", err), payload),
		}
	}
	if registeredClaims == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(motmedelJwtErrors.ErrNilRegisteredClaims),
		}
	}

	sessionToken := session_token.Token{Claims: registeredClaims}
	var errs []error

	rolesAny, rolesOk := payload["roles"]
	if rolesOk {
		roles, err := utils.ConvertSlice[string](rolesAny)
		if err == nil {
			sessionToken.Roles = roles
		} else {
			errs = append(errs, fmt.Errorf("convert slice (roles): %w", err))
		}
	} else {
		errs = append(errs, &motmedelJwtErrors.MissingRequiredFieldError{Name: "roles"})
	}

	tenantIdAny, tenantIdOk := payload["tenant_id"]
	if tenantIdOk {
		tenantId, err := utils.Convert[string](tenantIdAny)
		if err == nil {
			sessionToken.TenantId = tenantId
		} else {
			errs = append(errs, fmt.Errorf("convert (tenant id): %w", err))
		}
	}

	tenantNameAny, tenantNameOk := payload["tenant_name"]
	if tenantNameOk {
		tenantName, err := utils.Convert[string](tenantNameAny)
		if err == nil {
			sessionToken.TenantName = tenantName
		} else {
			errs = append(errs, fmt.Errorf("convert (tenant name): %w", err))
		}
	}

	subjectId, subjectEmail, found := strings.Cut(sessionToken.Subject, ":")
	if found {
		sessionToken.SubjectId = subjectId
		sessionToken.SubjectEmailAddress = subjectEmail
	}

	if len(errs) > 0 {
		return nil, &response_error.ResponseError{
			ClientError: errors.Join(errs...),
			ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
				http.StatusUnauthorized,
				"Invalid token.",
				nil,
			),
		}
	}

	if superAdminRoles := parser.SuperAdminRoles; len(superAdminRoles) != 0 {
		for _, role := range sessionToken.Roles {
			if slices.Contains(superAdminRoles, role) {
				return &sessionToken, nil
			}
		}
	}

	var allowed bool

	if allowedTenantId := parser.AllowedTenantId; allowedTenantId != "" {
		if sessionToken.TenantId != allowedTenantId {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
					http.StatusForbidden,
					"Invalid tenant id.",
					nil,
				),
			}
		}
	}

	if allowedRoles := parser.AllowedRoles; len(allowedRoles) != 0 {
		for _, role := range sessionToken.Roles {
			if slices.Contains(parser.AllowedRoles, role) {
				allowed = true
				break
			}
		}
	} else {
		allowed = true
	}

	if !allowed {
		return nil, &response_error.ResponseError{
			ProblemDetail: problem_detail.MakeStatusCodeProblemDetail(
				http.StatusForbidden,
				"Invalid role.",
				nil,
			),
		}
	}

	return &sessionToken, nil
}
