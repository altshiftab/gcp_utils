package authentication

import (
	"time"

	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/database/account"
)

type Authentication struct {
	Id               string           `postgres:"id,primarykey,type:uuid,default:gen_random_uuid()"`
	Account          *account.Account `postgres:"account,ondelete:CASCADE"`
	DbscPublicKey    []byte           `postgres:"dbsc_public_key,nullable"`
	CreatedAt        *time.Time       `postgres:"created_at"`
	ExpiresAt        *time.Time       `postgres:"expires_at"`
	Ended            bool             `postgres:"ended"`
	IpAddress        string           `postgres:"ip_address,type:inet,nullable"`
	IpAddressCountry string           `postgres:"ip_address_country,nullable"`
	UserAgent        string           `postgres:"user_agent,nullable"`
}
