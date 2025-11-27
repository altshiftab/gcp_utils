package types

type CallbackUrlInput struct {
	State        string `json:"state"`
	Code     string `json:"code"`
	Scope    string `json:"scope"`
	AuthUser int    `json:"authuser"`
	HostedDomain string `json:"hd"`
	Prompt       string `json:"prompt"`
}

type OauthFlow struct {
	State        string
	CodeVerifier string
	RedirectUrl  string
}
