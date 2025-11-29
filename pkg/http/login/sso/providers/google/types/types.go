package types

import (
	"errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
)

type GoogleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
	Hd            string `json:"hd"`
}

var (
	ErrNilEndpointSpecificationOverview = errors.New("nil endpoint specification overview")
)

type EndpointSpecificationOverview struct {
	LoginEndpoint    *endpoint_specification.EndpointSpecification
	CallbackEndpoint *endpoint_specification.EndpointSpecification
	FedCmEndpoint    *endpoint_specification.EndpointSpecification
	TokenEndpoint    *endpoint_specification.EndpointSpecification
}
