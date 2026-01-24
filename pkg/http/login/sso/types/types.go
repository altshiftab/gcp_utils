package types

type CallbackUrlInput struct {
	State        string `json:"state"`
	Code         string `json:"code"`
	Scope        string `json:"scope,omitempty"`
	AuthUser     int    `json:"authuser,omitempty"`
	HostedDomain string `json:"hd,omitempty"`
	Prompt       string `json:"prompt,omitempty"`
	SessionState string `json:"session_state,omitempty"`
}

type OauthFlow struct {
	State        string
	CodeVerifier string
	RedirectUrl  string
}

type FedCmInput struct {
	Token string `json:"token,omitempty" jsonschema:"token"`
}

type TokenInput struct {
	Code     string `json:"code,omitempty" jsonschema:"code"`
	Verifier string `json:"verifier,omitempty" jsonschema:"verifier"`
}
