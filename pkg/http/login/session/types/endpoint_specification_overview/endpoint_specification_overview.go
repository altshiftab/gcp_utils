package endpoint_specification_overview

import "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"

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
