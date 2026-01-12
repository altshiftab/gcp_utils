package types

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtilsJwt "github.com/Motmedel/utils_go/pkg/http/mux/utils/jwt"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelJwtErrors "github.com/Motmedel/utils_go/pkg/jwt/errors"
	"github.com/Motmedel/utils_go/pkg/jwt/types/registered_claims"
	motmedelUtils "github.com/Motmedel/utils_go/pkg/utils"
)

var (
	ErrNilEndpointSpecificationOverview = errors.New("nil endpoint specification overview")
)

type EndpointSpecificationOverview struct {
	RefreshEndpoint *endpoint_specification.EndpointSpecification
	EndEndpoint     *endpoint_specification.EndpointSpecification
}

func (overview *EndpointSpecificationOverview) Endpoints() []*endpoint_specification.EndpointSpecification {
	return []*endpoint_specification.EndpointSpecification{
		overview.RefreshEndpoint,
		overview.EndEndpoint,
	}
}

type JwtToken struct {
	*registered_claims.RegisteredClaims
	SubjectId           string
	SubjectEmailAddress string
	TenantId            string
	TenantName          string
	Roles               []string
}

func (token *JwtToken) GetUser() *motmedelHttpTypes.HttpContextUser {
	user := &motmedelHttpTypes.HttpContextUser{
		Id:    token.SubjectId,
		Email: token.SubjectEmailAddress,
	}

	if token.TenantId != "" || token.TenantName != "" {
		user.Group = &motmedelHttpTypes.HttpContextGroup{
			Id:   token.TenantId,
			Name: token.TenantName,
		}
	}

	user.Roles = token.Roles

	return user
}

type JwtTokenRequestParser struct {
	request_parser.RequestParser[*muxUtilsJwt.TokenWithRaw]

	AllowedRoles    []string
	AllowedTenantId string
	SuperAdminRoles []string
}

func (parser *JwtTokenRequestParser) Parse(request *http.Request) (*JwtToken, *response_error.ResponseError) {
	tokenWithRaw, responseError := parser.RequestParser.Parse(request)
	if responseError != nil {
		return nil, responseError
	}
	if tokenWithRaw == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(motmedelJwtErrors.ErrNilToken),
		}
	}

	payload := tokenWithRaw.Payload
	registeredClaims, err := registered_claims.FromMap(payload)
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

	jwtToken := JwtToken{RegisteredClaims: registeredClaims}
	var errs []error

	rolesAny, rolesOk := payload["roles"]
	if rolesOk {
		roles, err := motmedelUtils.ConvertSlice[string](rolesAny)
		if err == nil {
			jwtToken.Roles = roles
		} else {
			errs = append(errs, fmt.Errorf("convert slice (roles): %w", err))
		}
	} else {
		errs = append(errs, &motmedelJwtErrors.MissingRequiredFieldError{Name: "roles"})
	}

	tenantIdAny, tenantIdOk := payload["tenant_id"]
	if tenantIdOk {
		tenantId, err := motmedelUtils.Convert[string](tenantIdAny)
		if err == nil {
			jwtToken.TenantId = tenantId
		} else {
			errs = append(errs, fmt.Errorf("convert (tenant id): %w", err))
		}
	}

	tenantNameAny, tenantNameOk := payload["tenant_name"]
	if tenantNameOk {
		tenantName, err := motmedelUtils.Convert[string](tenantNameAny)
		if err == nil {
			jwtToken.TenantName = tenantName
		} else {
			errs = append(errs, fmt.Errorf("convert (tenant name): %w", err))
		}
	}

	subjectId, subjectEmail, found := strings.Cut(jwtToken.Subject, ":")
	if found {
		jwtToken.SubjectId = subjectId
		jwtToken.SubjectEmailAddress = subjectEmail
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
		for _, role := range jwtToken.Roles {
			if slices.Contains(superAdminRoles, role) {
				return &jwtToken, nil
			}
		}
	}

	var allowed bool

	if allowedTenantId := parser.AllowedTenantId; allowedTenantId != "" {
		if jwtToken.TenantId != allowedTenantId {
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
		for _, role := range jwtToken.Roles {
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

	return &jwtToken, nil
}
