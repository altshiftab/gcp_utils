package types

import (
	"fmt"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
)

var (
	ErrNilEndpointSpecificationOverview = fmt.Errorf("nil endpoint specification overview")
)

type EndpointSpecificationOverview struct {
    RefreshEndpoint    *endpoint_specification.EndpointSpecification
    RegisterEndpoint *endpoint_specification.EndpointSpecification
}

func (overview *EndpointSpecificationOverview) Endpoints() []*endpoint_specification.EndpointSpecification {
    return []*endpoint_specification.EndpointSpecification{
        overview.RefreshEndpoint,
        overview.RegisterEndpoint,
    }
}
