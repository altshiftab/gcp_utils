package session_registration_response


type Scope struct {
	Origin        string `json:"origin,omitempty"`
	IncludeSite   bool   `json:"include_site,omitempty"`
	DeferRequests bool   `json:"defer_requests,omitempty"`
}

type Credential struct {
	Type       string `json:"type,omitempty"`
	Name       string `json:"name,omitempty"`
	Attributes string `json:"attributes,omitempty"`
}

type SessionRegistrationResponse struct {
	SessionIdentifier string       `json:"session_identifier"`
	RefreshURL        string       `json:"refresh_url"`
	Scope             Scope        `json:"scope"`
	Credentials       []Credential `json:"credentials"`
}
