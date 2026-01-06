package types

import (
	"github.com/altshiftab/gcp_utils/pkg/http/client_code_generation/types/template_options"
)

type TemplateInput struct {
	Name                      string
	InputType                 string
	ReturnType                string
	URL                       string
	Method                    string
	ContentType               string
	ExpectedOutputContentType string
	OptionalOutput            bool
	UseAuthentication         bool
}

type GlobalTemplateInput struct {
	CseClientPublicJwkHeader string
	CseContentEncryption     string
	CseKeyAlgorithm          string
	CseKeyAlgorithmCurve     string
	CseServerPublicJwk       string
	UseEncryption            bool
	AuthenticationMode       template_options.AuthenticationMode
	AcceptBaseUrlArgument    bool
}
