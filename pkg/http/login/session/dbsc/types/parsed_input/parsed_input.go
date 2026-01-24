package parsed_input

import "github.com/altshiftab/gcp_utils/pkg/http/login/session/dbsc/types/session_response_processor"

type Input struct {
	DbscSessionId    string
	AuthenticationId string
	*session_response_processor.Output
}
