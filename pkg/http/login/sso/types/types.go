package types

type CallbackUrlInput struct {
	State        string `json:"state"`
	Code         string `json:"code"`
	Scopes       string `json:"scopes"`
	AuthUser     int    `json:"authuser"`
	HostedDomain string `json:"hd"`
	Prompt       string `json:"prompt"`
}

type OauthFlow struct {
	State        string
	CodeVerifier string
	RedirectUrl  string
}
