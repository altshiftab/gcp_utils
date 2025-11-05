package types

import (
	"reflect"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	"github.com/altshiftab/gcp_utils/pkg/http/client_code_generation/types/template_options"
)

type EndpointSpecificationGetter interface {
	GetEndpointSpecification() *endpoint_specification.EndpointSpecification
	GetExpectedOutputContentType() string
}

type TypedEndpointSpecification[T any, U any] struct {
	*endpoint_specification.EndpointSpecification
	Input                     T
	Output                    U
	OptionalOutput            bool
	ExpectedOutputContentType string
}

func (t TypedEndpointSpecification[T, U]) GetEndpointSpecification() *endpoint_specification.EndpointSpecification {
	return t.EndpointSpecification
}

func (t TypedEndpointSpecification[T, U]) GetExpectedOutputContentType() string {
	return t.ExpectedOutputContentType
}

type EndpointData struct {
	EndpointSpecification *endpoint_specification.EndpointSpecification
	Input                 reflect.Type
	Output                reflect.Type
	OutputContentType     string
}

type TemplateInput struct {
	Name                      string
	InputType                 string
	ReturnType                string
	URL                       string
	Method                    string
	ContentType               string
	ExpectedOutputContentType string
	UseAuthentication         bool
}

type GlobalTemplateInput struct {
	CseClientPublicJwkHeader string
	CseContentEncryption     string
	CseKeyAlgorithm          string
	CseKeyAlgorithmCurve     string
	CseServerPublicJwk       string
	UseEncryption   bool
	AuthenticationMode template_options.AuthenticationMode
}
