package types

import (
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
)

type EndpointSpecificationOverview struct {
	RefreshEndpoint    *endpoint_specification.EndpointSpecification
	RegisterEndpoint *endpoint_specification.EndpointSpecification
}
