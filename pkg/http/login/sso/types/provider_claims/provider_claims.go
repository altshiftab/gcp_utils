package provider_claims

type GoogleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
	Hd            string `json:"hd"`
}

type MicrosoftClaims struct {
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Upn               string `json:"upn"`
	Sub               string `json:"sub"`
	Tid               string `json:"tid"`
}
