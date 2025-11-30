package types

import (
    "errors"
    "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
)

type MicrosoftClaims struct {
    Email             string `json:"email"`
    PreferredUsername string `json:"preferred_username"`
    Upn               string `json:"upn"`
    Sub               string `json:"sub"`
    Tid               string `json:"tid"`
}

var (
    ErrNilEndpointSpecificationOverview = errors.New("nil endpoint specification overview")
)

type EndpointSpecificationOverview struct {
    LoginEndpoint    *endpoint_specification.EndpointSpecification
    CallbackEndpoint *endpoint_specification.EndpointSpecification
    TokenEndpoint    *endpoint_specification.EndpointSpecification
}

func (overview *EndpointSpecificationOverview) Endpoints() []*endpoint_specification.EndpointSpecification {
    return []*endpoint_specification.EndpointSpecification{
        overview.LoginEndpoint,
        overview.CallbackEndpoint,
        overview.TokenEndpoint,
    }
}
