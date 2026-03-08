package js_error_report

type ErrorDetails struct {
	Message string `json:"message,omitempty"`
	Cause   any    `json:"cause,omitempty"`
	Stack   string `json:"stack,omitempty"`
	Name    string `json:"name,omitempty"`
	Code    int    `json:"code,omitempty"`
}

type BaseErrorBody struct {
	Type  string        `json:"type"`
	Raw   string        `json:"raw,omitempty"`
	Error *ErrorDetails `json:"error,omitempty"`
}

type ErrorBody struct {
	BaseErrorBody
	ColNo    int    `json:"colno"`
	Filename string `json:"filename"`
	LineNo   int    `json:"lineno"`
	Message  string `json:"message"`
}
