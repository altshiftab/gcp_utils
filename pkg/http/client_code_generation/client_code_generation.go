package client_code_generation

import (
	"bytes"
	_ "embed"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"text/template"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	endpointPkg "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	clientCodeGenerationTypes "github.com/altshiftab/gcp_utils/pkg/http/client_code_generation/types"
	"github.com/altshiftab/gcp_utils/pkg/http/client_code_generation/types/template_options"
	typeGenerationTypescriptTypes "github.com/vphpersson/type_generation/pkg/producers/typescript/types"
	typeGenerationTypesContext "github.com/vphpersson/type_generation/pkg/types/context"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

//go:embed script.ts.tmpl
var scriptTemplateData string

var scriptTemplate = template.Must(
	template.New("script").Funcs(template.FuncMap{
		"dict": func(values ...any) (map[string]any, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict expects an even number of args")
			}
			m := make(map[string]any, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings, got %T", values[i])
				}
				m[key] = values[i+1]
			}
			return m, nil
		},
		// hasPrefix exposes strings.HasPrefix to templates
		"hasPrefix": func(s, prefix string) bool { return strings.HasPrefix(s, prefix) },
	}).Parse(scriptTemplateData),
)

func makeTypescriptContext(endpoints []*endpointPkg.Endpoint) (*typeGenerationTypescriptTypes.Context, error) {
	typesSet := make(map[reflect.Type]struct{})

	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}

		hint := endpoint.Hint
		if hint == nil {
			continue
		}

		typesSet[hint.InputType] = struct{}{}
		typesSet[hint.OutputType] = struct{}{}
	}

	var typeElements []any
	for t := range typesSet {
		if t == nil {
			continue
		}
		typeElements = append(typeElements, t)
	}

	tsContext := typeGenerationTypescriptTypes.Context{Context: typeGenerationTypesContext.New()}
	if err := tsContext.Add(typeElements...); err != nil {
		return nil, motmedelErrors.New(fmt.Errorf("typescript context add: %w", err), typeElements)
	}

	return &tsContext, nil
}

var emptyInterfaceType = reflect.TypeFor[any]()

func makePathPart(path string) string {
	caser := cases.Title(language.English, cases.NoLower)

	segments := strings.Split(
		strings.ReplaceAll(
			strings.TrimPrefix(
				path,
				"/api/",
			),
			"/",
			"-",
		),
		"-",
	)

	var casedSegments []string
	for _, segment := range segments {
		casedSegments = append(casedSegments, caser.String(segment))
	}

	return strings.Join(casedSegments, "")
}

func isEmptyInterfaceType(t reflect.Type) bool {
	if t == nil {
		return true
	}
	return t == emptyInterfaceType || (t.Kind() == reflect.Interface && t.NumMethod() == 0)
}

func makeTemplateInput(
	endpoints []*endpointPkg.Endpoint,
	tsContext *typeGenerationTypescriptTypes.Context,
	baseUrl *url.URL,
) ([]*clientCodeGenerationTypes.TemplateInput, error) {
	if tsContext == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("typescript context"))
	}

	if len(endpoints) == 0 {
		return nil, nil
	}

	var templateInputs []*clientCodeGenerationTypes.TemplateInput

	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}

		method := endpoint.Method
		if method == "" {
			return nil, motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrEmptyMethod, endpoint)
		}

		path := endpoint.Path
		if path == "" {
			return nil, motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrEmptyUrl, endpoint)
		}

		var outputContentType string
		var optionalOutput bool
		var typescriptInputType string
		var typescriptOutputType string

		if hint := endpoint.Hint; hint != nil {
			outputContentType = hint.OutputContentType
			optionalOutput = hint.OutputOptional

			inputType := hint.InputType
			if isEmptyInterfaceType(inputType) {
				typescriptInputType = "void"
			} else {
				typeScriptType, err := tsContext.GetTypeScriptType(inputType)
				if err != nil {
					return nil, motmedelErrors.New(
						fmt.Errorf("typescript context get typescript type (input): %w", err),
						inputType,
					)
				}
				typescriptInputType, err = typeScriptType.String()
				if err != nil {
					return nil, motmedelErrors.New(fmt.Errorf("typescript type string (output): %w", err), typeScriptType)
				}
			}

			outputTpe := hint.OutputType
			if isEmptyInterfaceType(outputTpe) {
				typescriptOutputType = "void"
			} else {
				typeScriptType, err := tsContext.GetTypeScriptType(outputTpe)
				if err != nil {
					return nil, motmedelErrors.New(
						fmt.Errorf("typescript context get typescript type (output): %w", err),
						outputTpe,
					)
				}
				typescriptOutputType, err = typeScriptType.String()
				if err != nil {
					return nil, motmedelErrors.New(
						fmt.Errorf("typescript type string (output): %w", err),
						outputTpe,
					)
				}
			}
		}

		var contentType string
		bodyLoader := endpoint.BodyLoader
		if bodyLoader != nil {
			contentType = bodyLoader.ContentType
		}

		useAuthentication := !endpoint.Public

		var urlString string
		if baseUrl != nil {
			urlString = baseUrl.String() + path
		} else {
			urlString = path
		}

		templateInputs = append(
			templateInputs,
			&clientCodeGenerationTypes.TemplateInput{
				Name: fmt.Sprintf(
					"%s%s",
					strings.ToLower(method),
					makePathPart(path),
				),
				InputType:                 typescriptInputType,
				ReturnType:                typescriptOutputType,
				URL:                       urlString,
				Method:                    endpoint.Method,
				ContentType:               contentType,
				ExpectedOutputContentType: outputContentType,
				UseAuthentication:         useAuthentication,
				OptionalOutput:            optionalOutput,
			},
		)
	}

	return templateInputs, nil
}

func Render(
	endpoints []*endpointPkg.Endpoint,
	baseUrl *url.URL,
	options ...template_options.Option,
) (string, error) {
	if len(endpoints) == 0 {
		return "", nil
	}

	tsContext, err := makeTypescriptContext(endpoints)
	if err != nil {
		return "", fmt.Errorf("make typescript context: %w", err)
	}

	templateInputs, err := makeTemplateInput(endpoints, tsContext, baseUrl)
	if err != nil {
		return "", motmedelErrors.New(fmt.Errorf("make template input: %w", err), tsContext)
	}

	var useEncryption bool
	for _, templateInput := range templateInputs {
		// Determine if any endpoint requires encryption (either request or response)
		if templateInput.ContentType == "application/jose" || templateInput.ExpectedOutputContentType == "application/jose" {
			useEncryption = true
		}
	}

	templateOptions := template_options.New(options...)

	tsContextOutput, err := tsContext.Render()
	if err != nil {
		return "", motmedelErrors.New(fmt.Errorf("typescript context render: %w", err), tsContext)
	}

	var buffer bytes.Buffer
	data := map[string]any{
		"Endpoints": templateInputs,
		"Globals": &clientCodeGenerationTypes.GlobalTemplateInput{
			CseClientPublicJwkHeader: templateOptions.CseClientPublicJwkHeader,
			CseContentEncryption:     templateOptions.CseContentEncryption,
			CseKeyAlgorithm:          templateOptions.CseKeyAlgorithm,
			CseKeyAlgorithmCurve:     templateOptions.CseKeyAlgorithmCurve,
			UseEncryption:            useEncryption,
			AuthenticationMode:       templateOptions.AuthenticationMode,
			AcceptBaseUrlArgument:    templateOptions.AcceptBaseUrlArgument,
		},
	}
	if err := scriptTemplate.Execute(&buffer, data); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("template execute: %w", err), data)
	}

	return fmt.Sprintf("%s\n%s\n", tsContextOutput, buffer.String()), nil
}
