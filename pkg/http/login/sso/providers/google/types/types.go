package types

import "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"

type FedCmInput struct {
	Token string   `json:"token,omitempty" required:"true" minLength:"1"`
	_     struct{} `additionalProperties:"false"`
}

type GoogleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
	Hd            string `json:"hd"`
}

type EndpointSpecificationOverview struct {
	LoginEndpoint *endpoint_specification.EndpointSpecification
	CallbackEndpoint *endpoint_specification.EndpointSpecification
	FedCmEndpoint *endpoint_specification.EndpointSpecification
}