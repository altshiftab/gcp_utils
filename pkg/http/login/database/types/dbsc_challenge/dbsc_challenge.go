package dbsc_challenge

import (
	"time"

	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/authentication"
)

type Challenge struct {
	Authentication *authentication.Authentication `postgres:"authentication,ondelete:CASCADE"`
	Challenge      []byte                         `postgres:"challenge"`
	ExpiresAt      *time.Time                     `postgres:"expires_at"`
}
