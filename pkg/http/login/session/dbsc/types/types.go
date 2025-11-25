package types

import (
	"net/url"
	"time"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
)

type Configuration struct {
	OriginUrl         *url.URL
	RegisterPath      string
	RefreshPath       string
	AllowedAlgs       []string
	ChallengeDuration time.Duration
}

type EndpointSpecificationOverview struct {
	RefreshEndpoint    *endpoint_specification.EndpointSpecification
	RegisterEndpoint *endpoint_specification.EndpointSpecification
}
