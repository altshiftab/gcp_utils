package http

import (
	"context"
	"github.com/Motmedel/ecs_go/ecs"
	"github.com/Motmedel/gcp_logging_go/gcp_logging"
	motmedelGcpUtilsEnv "github.com/Motmedel/motmedel_gcp_utils/pkg/env"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelMux "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTypes "github.com/Motmedel/utils_go/pkg/http/mux/types"
	"github.com/Motmedel/utils_go/pkg/http/problem_detail"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelJson "github.com/Motmedel/utils_go/pkg/json"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"log/slog"
	"net/http"
)

func getHttpContextLogAttrs(httpContext *motmedelHttpTypes.HttpContext) []any {
	if httpContext == nil {
		return nil
	}

	logger := slog.Default()
	if request := httpContext.Request; request != nil {
		logger = motmedelLog.GetLoggerFromCtxWithDefault(request.Context(), nil)
	}

	var logAttrs []any

	ecsBase, err := ecs.ParseHttpContext(httpContext, ecs.DefaultMaskedHeaderExtractor)
	if err != nil {
		motmedelLog.LogError("An error occurred when parsing an HTTP context into ECS.", err, logger)
	}
	if ecsBase != nil {
		if baseMap, ok := motmedelJson.Jsonify(ecsBase).(map[string]any); ok {
			logAttrs = append(logAttrs, motmedelLog.AttrsFromMap(baseMap)...)
		} else {
			msg := "An ECS base object could not be converted into a jsonified map."
			motmedelLog.LogError(msg, &motmedelErrors.InputError{Message: msg, Input: ecsBase}, logger)
		}
	}

	gcpLogEntry, err := gcp_logging.ParseHttp(httpContext.Request, httpContext.Response)
	if err != nil {
		motmedelLog.LogError("An error occurred when parsing HTTP data into GCP LogEntry.", err, logger)
	}
	if gcpLogEntry != nil {
		if gcpLogEntryMap, ok := motmedelJson.Jsonify(ecsBase).(map[string]any); ok {
			logAttrs = append(logAttrs, motmedelLog.AttrsFromMap(gcpLogEntryMap)...)
		} else {
			msg := "A GCP LogEntry object could not be converted into a jsonified map."
			motmedelLog.LogError(msg, &motmedelErrors.InputError{Message: msg, Input: gcpLogEntry}, logger)
		}
	}

	return logAttrs
}

func performLoggedErrorResponse(
	responseWriter http.ResponseWriter,
	request *http.Request,
	requestBody []byte,
	problemDetail *problem_detail.ProblemDetail,
	headers []*muxTypes.HeaderEntry,
	muxError error,
) {
	logger := slog.Default()
	if request != nil {
		logger = motmedelLog.GetLoggerFromCtxWithDefault(request.Context(), nil)
	}

	// Perform an HTTP response indicating an error occurred.

	motmedelMux.WriteProblemDetailResponse(responseWriter, request, problemDetail, headers)

	// Log the error information alongside the HTTP request and response data.

	// Add error context to the log entry.

	logLevel := slog.LevelError
	message := "An error occurred."
	var logAttrs []any

	if problemDetail != nil {
		statusCode := problemDetail.Status
		if statusCode >= 400 && statusCode < 500 {
			logLevel = slog.LevelWarn
			message = "A client error occurred."
		} else if statusCode >= 500 && statusCode < 600 {
			logLevel = slog.LevelError
			message = "A server error occurred."
		}

		if problemDetailInstance := problemDetail.Instance; problemDetailInstance != "" {
			logAttrs = append(logAttrs, slog.Group("error", slog.String("id", problemDetailInstance)))
		}
	}

	if muxError != nil {
		if errAttr := motmedelLog.MakeErrorGroup(muxError); errAttr != nil {
			logAttrs = append(logAttrs, *errAttr)
		}
	}

	// Add HTTP metadata to the log entry. Use both ECS and the GCP LogEntry structure.

	httpContext := &motmedelHttpTypes.HttpContext{Request: request, RequestBody: requestBody}

	if customResponseWriter, ok := responseWriter.(*muxTypes.ResponseWriter); !ok {
		logger.Error("A response writer could not be converted into a custom response writer.")
	} else {
		httpContext.Response = &http.Response{
			StatusCode: customResponseWriter.WrittenStatusCode,
			Header:     customResponseWriter.Header(),
		}
		httpContext.ResponseBody = customResponseWriter.WrittenBody
	}

	logAttrs = append(logAttrs, getHttpContextLogAttrs(httpContext)...)

	// Perform the logging.

	logger.Log(context.Background(), logLevel, message, logAttrs...)
}

func SuccessLogCallback(request *http.Request, requestBody []byte, response *http.Response, responseBody []byte) {
	logger := slog.Default()
	if request != nil {
		logger = motmedelLog.GetLoggerFromCtxWithDefault(request.Context(), nil)
	}

	logger.Log(
		context.Background(),
		slog.LevelDebug,
		"An HTTP response was served.",
		getHttpContextLogAttrs(
			&motmedelHttpTypes.HttpContext{
				Request:      request,
				RequestBody:  requestBody,
				Response:     response,
				ResponseBody: responseBody,
			},
		)...,
	)
}

func PatchMux(mux *motmedelMux.Mux) {
	if mux == nil {
		return
	}

	mux.ServerErrorHandler = func(
		responseWriter http.ResponseWriter,
		request *http.Request,
		requestBody []byte,
		problemDetail *problem_detail.ProblemDetail,
		headers []*muxTypes.HeaderEntry,
		err error,
	) {
		if problemDetail == nil {
			problemDetail = problem_detail.MakeInternalServerErrorProblemDetail("", nil)
		}
		performLoggedErrorResponse(responseWriter, request, requestBody, problemDetail, headers, err)
	}

	mux.ClientErrorHandler = func(
		responseWriter http.ResponseWriter,
		request *http.Request,
		requestBody []byte,
		problemDetail *problem_detail.ProblemDetail,
		headers []*muxTypes.HeaderEntry,
		err error,
	) {
		if problemDetail == nil {
			problemDetail = problem_detail.MakeBadRequestProblemDetail("", nil)
		}
		performLoggedErrorResponse(responseWriter, request, requestBody, problemDetail, headers, err)
	}

	mux.Middleware = append(
		mux.Middleware,
		func(request *http.Request) *http.Request {
			if request == nil {
				return nil
			}

			requestContext := request.Context()

			logger, ok := requestContext.Value(motmedelLog.LoggerCtxKey).(*slog.Logger)
			if !ok || logger == nil {
				return request
			}

			requestId, ok := requestContext.Value(motmedelMux.RequestIdContextKey).(string)
			if !ok || requestId == "" {
				return request
			}

			return request.WithContext(
				context.WithValue(
					requestContext,
					motmedelLog.LoggerCtxKey,
					logger.With(
						slog.Group(
							"labels",
							slog.String("request_id", requestId),
						),
					),
				),
			)
		},
	)

	if motmedelGcpUtilsEnv.GetLogLevelWithDefault() == "DEBUG" {
		mux.SuccessCallback = SuccessLogCallback
	}
}

func MakeMux(specifications []*muxTypes.HandlerSpecification, contextKeyValuePairs [][2]any) *motmedelMux.Mux {

	mux := &motmedelMux.Mux{}
	mux.SetContextKeyValuePairs = contextKeyValuePairs
	mux.Add(specifications...)

	PatchMux(mux)

	return mux
}
