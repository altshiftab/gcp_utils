package types

import (
	"github.com/altshiftab/gcp_utils/pkg/http/client_code_generation/types/template_options"
)

type TemplateInput struct {
	Name                      string
	InputType                 string
	UrlInputType              string
	ReturnType                string
	URL                       string
	Method                    string
	ContentType               string
	ExpectedOutputContentType string
	OptionalOutput            bool
	UseAuthentication         bool
	// BinaryOutput marks endpoints whose response body is binary (an output
	// content type that is neither JSON-ish, text/*, JOSE, nor COSE). The
	// generated function returns the body as a Blob without reading it as text.
	BinaryOutput bool
}

type GlobalTemplateInput struct {
	CseClientPublicJwkHeader string
	CseContentEncryption     string
	CseKeyAlgorithm          string
	CseKeyAlgorithmCurve     string
	CseServerPublicJwk       string
	UseEncryption            bool
	UseCose                  bool
	HasBinaryOutput          bool
	AuthenticationMode       template_options.AuthenticationMode
	AcceptBaseUrlArgument    bool
}
