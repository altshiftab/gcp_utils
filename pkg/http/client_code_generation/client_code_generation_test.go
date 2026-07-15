package client_code_generation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader"
	endpointPkg "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
)

type uploadInput struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

type uploadOutput struct {
	Id string `json:"id"`
}

type coseUploadDocument struct {
	FileName string `json:"file_name"`
	Content  []byte `json:"content"`
}

type coseUploadInput struct {
	Name      string                `json:"name"`
	Documents []*coseUploadDocument `json:"documents,omitzero"`
}

func TestRenderMultipartFormData(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "POST",
			Path:   "/api/upload",
			BodyLoader: &body_loader.Loader{
				ContentType: "multipart/form-data",
			},
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[uploadInput](),
				OutputType:        reflect.TypeFor[uploadOutput](),
				OutputContentType: "application/json",
			},
		},
	}

	output, err := Render(endpoints, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if !strings.Contains(output, "input: FormData") {
		t.Errorf("expected FormData input parameter, got:\n%s", output)
	}

	if strings.Contains(output, `"Content-Type":`) {
		t.Errorf("expected no Content-Type header for multipart/form-data, got:\n%s", output)
	}

	if strings.Contains(output, "UploadInput") {
		t.Errorf("expected no generated interface for the multipart input type, got:\n%s", output)
	}

	if !strings.Contains(output, "const data = input;") {
		t.Errorf("expected FormData body passthrough, got:\n%s", output)
	}

	if !strings.Contains(output, "body: data,") {
		t.Errorf("expected body to be set, got:\n%s", output)
	}
}

func TestRenderUrlEncodedFormData(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "POST",
			Path:   "/api/upload",
			BodyLoader: &body_loader.Loader{
				ContentType: "application/x-www-form-urlencoded",
			},
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[uploadInput](),
				OutputType:        reflect.TypeFor[uploadOutput](),
				OutputContentType: "application/json",
			},
		},
	}

	output, err := Render(endpoints, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if !strings.Contains(output, "input: URLSearchParams") {
		t.Errorf("expected URLSearchParams input parameter, got:\n%s", output)
	}

	if strings.Contains(output, `"Content-Type":`) {
		t.Errorf("expected no Content-Type header for application/x-www-form-urlencoded, got:\n%s", output)
	}

	if strings.Contains(output, "UploadInput") {
		t.Errorf("expected no generated interface for the form input type, got:\n%s", output)
	}

	if !strings.Contains(output, "const data = input;") {
		t.Errorf("expected URLSearchParams body passthrough, got:\n%s", output)
	}
}

func TestRenderJson(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "POST",
			Path:   "/api/upload",
			BodyLoader: &body_loader.Loader{
				ContentType: "application/json",
			},
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[uploadOutput](),
				OutputType:        reflect.TypeFor[uploadOutput](),
				OutputContentType: "application/json",
			},
		},
	}

	output, err := Render(endpoints, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if !strings.Contains(output, `"Content-Type": "application/json",`) {
		t.Errorf("expected Content-Type header for application/json, got:\n%s", output)
	}

	if !strings.Contains(output, "JSON.stringify(input)") {
		t.Errorf("expected JSON body serialization, got:\n%s", output)
	}
}

func TestRenderCose(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "POST",
			Path:   "/api/upload",
			BodyLoader: &body_loader.Loader{
				ContentType: "application/cose",
			},
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[coseUploadInput](),
				OutputType:        reflect.TypeFor[uploadOutput](),
				OutputContentType: "application/json",
			},
		},
	}

	output, err := Render(endpoints, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	for _, expected := range []string{
		`import {encode as cborEncode} from "@altshiftab/utils/cbor";`,
		`import {encrypt as coseEncrypt} from "@altshiftab/utils/cose";`,
		"input: CoseUploadInput",
		"serverJwk: JsonWebKey & {kid?: string}",
		"content: Uint8Array;",
		"const data = await coseEncrypt(cborEncode(input), serverPublicKey, {",
		`contentType: "application/cbor",`,
		"keyIdentifier: new TextEncoder().encode(serverJwk.kid),",
		`"Content-Type": "application/cose",`,
		"body: data,",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %q, got:\n%s", expected, output)
		}
	}

	if strings.Contains(output, `from "jose"`) {
		t.Errorf("expected no jose import for a cose-only client, got:\n%s", output)
	}
}

func TestRenderJose(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "POST",
			Path:   "/api/upload",
			BodyLoader: &body_loader.Loader{
				ContentType: "application/jose",
			},
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[uploadInput](),
				OutputType:        reflect.TypeFor[uploadOutput](),
				OutputContentType: "application/json",
			},
		},
	}

	output, err := Render(endpoints, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	for _, expected := range []string{
		`from "jose"`,
		"serverJwk: JWK",
		"new CompactEncrypt(new TextEncoder().encode(JSON.stringify(input)))",
		`"Content-Type": "application/jose",`,
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %q, got:\n%s", expected, output)
		}
	}

	if strings.Contains(output, "@altshiftab/utils/cose") {
		t.Errorf("expected no cose import for a jose-only client, got:\n%s", output)
	}
}

func TestRenderCoseBodylessMethod(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "GET",
			Path:   "/api/upload",
			BodyLoader: &body_loader.Loader{
				ContentType: "application/cose",
			},
		},
	}

	if _, err := Render(endpoints, nil); err == nil {
		t.Error("expected an error for application/cose with a body-less method")
	}
}

func TestRenderCoseOutputUnsupported(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "POST",
			Path:   "/api/upload",
			BodyLoader: &body_loader.Loader{
				ContentType: "application/cose",
			},
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[coseUploadInput](),
				OutputType:        reflect.TypeFor[uploadOutput](),
				OutputContentType: "application/cose",
			},
		},
	}

	if _, err := Render(endpoints, nil); err == nil {
		t.Error("expected an error for an application/cose output content type")
	}
}

type documentInput struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

func TestRenderBinaryOutput(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "GET",
			Path:   "/api/document",
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[documentInput](),
				OutputContentType: "application/pdf",
			},
		},
	}

	output, err := Render(endpoints, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	for _, expected := range []string{
		`import {BadStatusCodeError} from "@altshiftab/utils/http/errors";`,
		`import {fetchEx, fetchWithRequest} from "@altshiftab/utils/http/utils";`,
		"input: DocumentInput",
		"): Promise<Blob> {",
		"const {response} = await fetchWithRequest(request, {skipReadResponseBody: true, skipErrorOnStatusCode: true});",
		`throw new BadStatusCodeError(response.status, {request, requestBody: "", response, responseBody});`,
		`if (contentType != "application/pdf") {`,
		"return await response.blob();",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %q, got:\n%s", expected, output)
		}
	}

	// The body must never be read as text for a binary endpoint.
	if strings.Contains(output, "responseText") {
		t.Errorf("expected no text body handling for a binary endpoint, got:\n%s", output)
	}
}

func TestRenderNoBinaryImportsWithoutBinaryOutput(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "POST",
			Path:   "/api/upload",
			BodyLoader: &body_loader.Loader{
				ContentType: "application/json",
			},
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[uploadInput](),
				OutputType:        reflect.TypeFor[uploadOutput](),
				OutputContentType: "application/json",
			},
		},
	}

	output, err := Render(endpoints, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	for _, unexpected := range []string{"fetchWithRequest", "BadStatusCodeError"} {
		if strings.Contains(output, unexpected) {
			t.Errorf("expected output to not contain %q, got:\n%s", unexpected, output)
		}
	}
}

func TestRenderBinaryOutputWithOutputType(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "GET",
			Path:   "/api/document",
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[documentInput](),
				OutputType:        reflect.TypeFor[uploadOutput](),
				OutputContentType: "application/pdf",
			},
		},
	}

	if _, err := Render(endpoints, nil); err == nil {
		t.Error("expected an error for an output type combined with a binary output content type")
	}
}

func TestRenderBinaryOutputOptional(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "GET",
			Path:   "/api/document",
			Hint: &endpointPkg.Hint{
				InputType:         reflect.TypeFor[documentInput](),
				OutputContentType: "application/pdf",
				OutputOptional:    true,
			},
		},
	}

	if _, err := Render(endpoints, nil); err == nil {
		t.Error("expected an error for optional output combined with a binary output content type")
	}
}

func TestRenderMultipartFormDataBodylessMethod(t *testing.T) {
	endpoints := []*endpointPkg.Endpoint{
		{
			Method: "GET",
			Path:   "/api/upload",
			BodyLoader: &body_loader.Loader{
				ContentType: "multipart/form-data",
			},
		},
	}

	if _, err := Render(endpoints, nil); err == nil {
		t.Error("expected an error for multipart/form-data with a body-less method")
	}
}
