package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"

	motmedelEnv "github.com/Motmedel/utils_go/pkg/env"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelContextLogger "github.com/Motmedel/utils_go/pkg/log/context_logger"
	errorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	motmedelMaps "github.com/Motmedel/utils_go/pkg/maps"
	"github.com/vphpersson/code_generation/pkg/code_generation"
	"github.com/vphpersson/code_generation/pkg/translate"
)

const map16 = "abcdefghijklmnop"

func extensionIdFromKey(keyBase64 string) (string, error) {
	keyDer, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("base64 stdencoding decode string: %w", err))
	}

	sum := sha256.Sum256(keyDer)
	id := make([]byte, 32)
	for i := 0; i < 16; i++ {
		id[i*2] = map16[sum[i]>>4]
		id[i*2+1] = map16[sum[i]&0x0f]
	}

	return string(id), nil
}

func main() {
	logger := errorLogger.Logger{
		Logger: motmedelContextLogger.New(
			slog.NewJSONHandler(os.Stderr, nil),
			&motmedelLog.ErrorContextExtractor{},
		),
	}
	slog.SetDefault(logger.Logger)

	var path string
	flag.StringVar(&path, "path", "", "path to generate code from")

	var packageName string
	flag.StringVar(
		&packageName,
		"package-name",
		motmedelEnv.GetEnvWithDefault("GOPACKAGE", "main"),
		"The name of the package in the output.",
	)

	flag.Parse()

	if path == "" {
		logger.FatalWithExitingMessage("Empty path.", nil)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when reading the file.",
			motmedelErrors.NewWithTrace(fmt.Errorf("os read file: %w", err), path),
		)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when unmarshalling the file data.",
			motmedelErrors.NewWithTrace(fmt.Errorf("json unmarshal: %w", err), data),
		)
	}

	key, err := motmedelMaps.MapGetConvert[string](m, "key")
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when getting the key.",
			motmedelErrors.NewWithTrace(fmt.Errorf("map get convert: %w", err), m),
		)
	}

	extensionId, err := extensionIdFromKey(key)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when generating the extension id.",
			motmedelErrors.NewWithTrace(fmt.Errorf("extension id from key: %w", err), key),
		)
	}

	extensionIdMap := map[string]any{"extensionId": extensionId}
	code, err := translate.Map(extensionIdMap)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when translating the map.",
			motmedelErrors.New(fmt.Errorf("translate map: %w", err), extensionIdMap),
		)
	}

	output, err := code_generation.MakeFileContent(
		code,
		packageName,
		"infer_extension_id",
		nil,
	)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when generating the output file content.",
			motmedelErrors.New(fmt.Errorf("make file content: %w", err), code, packageName),
		)
	}

	if fileName := code_generation.GetGeneratedFilename(); fileName != "" {
		if err := os.WriteFile(fileName, output, 0644); err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when writing the file.",
				motmedelErrors.New(fmt.Errorf("os write file: %w", err), fileName, output),
			)
		}
	} else {
		fmt.Println(string(output))
	}
}
