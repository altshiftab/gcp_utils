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
