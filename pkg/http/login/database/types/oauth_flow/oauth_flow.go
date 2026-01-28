package oauth_flow

import "time"

type Flow struct {
	CodeVerifier string     `postgres:"code_verifier,unique"`
	State        string     `postgres:"state"`
	ExpiresAt    *time.Time `postgres:"expires_at"`
	RedirectUrl  string     `postgres:"redirect_url"`
}
