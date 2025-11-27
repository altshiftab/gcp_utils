package types

type CallbackUrlInput struct {
	State        string `json:"state"`
	Code         string `json:"code"`
	Scope        string `json:"scope"`
	AuthUser     int    `json:"authuser"`
	HostedDomain string `json:"hd"`
	Prompt       string `json:"prompt"`
}

type OauthFlow struct {
	State        string
	CodeVerifier string
	RedirectUrl  string
}

type FedCmInput struct {
	Token string   `json:"token,omitempty" required:"true" minLength:"1"`
	_     struct{} `additionalProperties:"false"`
}

type TokenInput struct {
	Code     string   `json:"code" required:"true" minLength:"1"`
	Verifier string   `json:"verifier" required:"true" minLength:"1"`
	_        struct{} `additionalProperties:"false"`
}
