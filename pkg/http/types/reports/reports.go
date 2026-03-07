package reports

type CspReport struct {
	DocumentUri        string `json:"document-uri,omitempty"`
	Referrer           string `json:"referrer,omitempty"`
	ViolatedDirective  string `json:"violated-directive,omitempty"`
	EffectiveDirective string `json:"effective-directive,omitempty"`
	OriginalPolicy     string `json:"original-policy,omitempty"`
	Disposition        string `json:"disposition,omitempty"`
	BlockedUri         string `json:"blocked-uri,omitempty"`
	LineNumber         int    `json:"line-number,omitempty"`
	ColumnNumber       int    `json:"column-number,omitempty"`
	SourceFile         string `json:"source-file,omitempty"`
	StatusCode         int    `json:"status-code,omitempty"`
	ScriptSample       string `json:"script-sample,omitempty"`
}

type CspReportWrapper struct {
	CspReport *CspReport `json:"csp-report,omitempty"`
}

type ReportBody struct {
	BlockedUrl         string `json:"blockedURL,omitempty"`
	ColumnNumber       int    `json:"columnNumber,omitempty"`
	Disposition        string `json:"disposition,omitempty"`
	DocumentUrl        string `json:"documentURL,omitempty"`
	EffectiveDirective string `json:"effectiveDirective,omitempty"`
	LineNumber         int    `json:"lineNumber,omitempty"`
	OriginalPolicy     string `json:"originalPolicy,omitempty"`
	Referrer           string `json:"referrer,omitempty"`
	Sample             string `json:"sample,omitempty"`
	SourceFile         string `json:"sourceFile,omitempty"`
	StatusCode         int    `json:"statusCode,omitempty"`
	Type               string `json:"type,omitempty"`
	Phase              string `json:"phase,omitempty"`
	ServerIp           string `json:"server_ip,omitempty"`
	Protocol           string `json:"protocol,omitempty"`
	Method             string `json:"method,omitempty"`
	ElapsedTime        int    `json:"elapsed_time,omitempty"`
	Destination        string `json:"destination,omitempty"`
}

type Report struct {
	Age       int        `json:"age,omitempty"`
	Body      ReportBody `json:"body"`
	Type      string     `json:"type,omitempty"`
	Url       string     `json:"url,omitempty"`
	UserAgent string     `json:"user_agent,omitempty"`
}

type JsErrorReport struct {
	Message  string `json:"message,omitempty"`
	Source   string `json:"source,omitempty"`
	LineNo   int    `json:"lineno,omitempty"`
	ColNo    int    `json:"colno,omitempty"`
	ErrorObj string `json:"error,omitempty"`
	Stack    string `json:"stack,omitempty"`
}

type UnhandledRejectionReport struct {
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Stack   string `json:"stack,omitempty"`
}
