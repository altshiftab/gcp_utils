package types

import "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"

type MicrosoftClaims struct {
    Email             string `json:"email"`
    PreferredUsername string `json:"preferred_username"`
    Upn               string `json:"upn"`
    Sub               string `json:"sub"`
    Tid               string `json:"tid"`
}

type EndpointSpecificationOverview struct {
    LoginEndpoint    *endpoint_specification.EndpointSpecification
    CallbackEndpoint *endpoint_specification.EndpointSpecification
    TokenEndpoint    *endpoint_specification.EndpointSpecification
}
