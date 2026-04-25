package js_error_report

type ErrorDetails struct {
	Message string `json:"message,omitzero"`
	Cause   any    `json:"cause,omitzero"`
	Stack   string `json:"stack,omitzero"`
	Name    string `json:"name,omitzero"`
	Code    int    `json:"code,omitzero"`
}

type BaseErrorBody struct {
	Type  string        `json:"type"`
	Raw   string        `json:"raw,omitzero"`
	Error *ErrorDetails `json:"error,omitzero"`
}

type ErrorBody struct {
	BaseErrorBody
	ColNo    int    `json:"colno"`
	Filename string `json:"filename"`
	LineNo   int    `json:"lineno"`
	Message  string `json:"message"`
}
