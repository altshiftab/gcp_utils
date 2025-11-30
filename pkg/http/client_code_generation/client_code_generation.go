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
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint_specification"
	motmedelNetErrors "github.com/Motmedel/utils_go/pkg/net/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	clientCodeGenerationTypes "github.com/altshiftab/gcp_utils/pkg/http/client_code_generation/types"
	"github.com/altshiftab/gcp_utils/pkg/http/client_code_generation/types/template_options"
	gcpUtilsHttpErrors "github.com/altshiftab/gcp_utils/pkg/http/errors"
	typeGenerationTypescriptErrors "github.com/vphpersson/type_generation/pkg/producers/typescript/errors"
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
	}).Parse(scriptTemplateData),
)

var caser = cases.Title(language.English, cases.NoLower)

func makeTypescriptContext(endpointSpecifications []*endpoint_specification.EndpointSpecification) (*typeGenerationTypescriptTypes.Context, error) {
	typesSet := make(map[reflect.Type]struct{})

	for _, endpointSpecification := range endpointSpecifications {
		if endpointSpecification == nil {
			continue
		}

		hint := endpointSpecification.Hint
		if hint == nil {
			continue
		}

		typesSet[hint.InputType] = struct{}{}
		typesSet[hint.OutputType] = struct{}{}
	}

	var typeElements []any
	for t := range typesSet {
		element := reflect.New(t).Elem().Interface()
		if utils.IsNil(element) {
			continue
		}

		typeElements = append(typeElements, element)
	}

	tsContext := typeGenerationTypescriptTypes.Context{Context: typeGenerationTypesContext.New()}
	if err := tsContext.Add(typeElements...); err != nil {
		return nil, motmedelErrors.New(fmt.Errorf("typescript context add: %w", err), typeElements)
	}

	return &tsContext, nil
}

var emptyInterfaceType = reflect.TypeOf((*interface{})(nil)).Elem()

func makePathPart(path string) string {
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
	endpointSpecifications []*endpoint_specification.EndpointSpecification,
	tsContext *typeGenerationTypescriptTypes.Context,
	baseUrl *url.URL,
) ([]*clientCodeGenerationTypes.TemplateInput, error) {

	if tsContext == nil {
		return nil, motmedelErrors.NewWithTrace(typeGenerationTypescriptErrors.ErrNilContext)
	}

	if baseUrl == nil {
		return nil, motmedelErrors.NewWithTrace(motmedelNetErrors.ErrNilUrl)
	}

	if len(endpointSpecifications) == 0 {
		return nil, nil
	}

	var templateInputs []*clientCodeGenerationTypes.TemplateInput

	for _, endpointSpecification := range endpointSpecifications {
		if endpointSpecification == nil {
			continue
		}

		method := endpointSpecification.Method
		if method == "" {
			return nil, motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrEmptyMethod, endpointSpecification)
		}

		path := endpointSpecification.Path
		if path == "" {
			return nil, motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrEmptyUrl, endpointSpecification)
		}

		var outputContentType string
		var optionalOutput bool
		var typescriptInputType string
		var typescriptOutputType string

		if hint := endpointSpecification.Hint; hint != nil {
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
		bodyParserConfiguration := endpointSpecification.BodyParserConfiguration
		if bodyParserConfiguration != nil {
			contentType = bodyParserConfiguration.ContentType
		}

		var useAuthentication bool
		if config := endpointSpecification.AuthenticationConfiguration; config != nil {
			useAuthentication = true
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
				URL:                       baseUrl.String() + path,
				Method:                    endpointSpecification.Method,
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
	endpointSpecifications []*endpoint_specification.EndpointSpecification,
	baseUrl *url.URL,
	options ...template_options.Option,
) (string, error) {
	if baseUrl == nil {
		return "", motmedelErrors.NewWithTrace(gcpUtilsHttpErrors.ErrNilBaseUrl)
	}

	if len(endpointSpecifications) == 0 {
		return "", nil
	}

	tsContext, err := makeTypescriptContext(endpointSpecifications)
	if err != nil {
		return "", fmt.Errorf("make typescript context: %w", err)
	}

	templateInputs, err := makeTemplateInput(endpointSpecifications, tsContext, baseUrl)
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
		},
	}
	if err := scriptTemplate.Execute(&buffer, data); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("template execute: %w", err), data)
	}

	return fmt.Sprintf("%s\n%s\n", tsContextOutput, buffer.String()), nil
}
