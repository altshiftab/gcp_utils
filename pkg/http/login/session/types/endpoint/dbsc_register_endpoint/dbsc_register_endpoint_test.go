package dbsc_register_endpoint

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/authentication"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/dbsc_challenge"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session"
	loginTesting "github.com/altshiftab/gcp_utils/pkg/http/login/session/testing"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/dbsc_session_response_processor"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/dbsc_session_response_processor/dbsc_session_response_processor_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_cookie"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var defaultSessionCookieString string
var defaultAuthorizationRequestParser *authorizer_request_parser.Parser
var defaultProcessor *dbsc_session_response_processor.Processor

var db *sql.DB
var method motmedelCryptoInterfaces.Method

func TestMain(m *testing.M) {
	var err error

	defaultAuthorizationRequestParser, method, db = loginTesting.SetUp()
	defaultProcessor, err = dbsc_session_response_processor.New("https://example.com"+dbsc_register_endpoint_config.DefaultPath, db)
	if err != nil {
		panic(fmt.Errorf("dbsc session response processor new: %w", err))
	}

	defaultSessionCookieString = loginTesting.MakeStandardCookie(loginTesting.AuthenticationId, method)

	code := m.Run()
	if db != nil {
		_ = db.Close()
	}
	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	const (
		validToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRic2Mrand0In0.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tL2FwaS9zZXNzaW9uL2Ric2MvcmVnaXN0ZXIiLCJqdGkiOiJjdiIsImlhdCI6MTcyNTU3OTA1NSwia2V5Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiSy1aSHM3cWo1RmtDZGhIeno4NFFzQ2FkOFFwVnNJdzVIRWdhQkZoeEN3TSIsInkiOiJwanUtWFVCdDN3TXhzRlBRdW9EVHNWcjU4SHREc2ZnOTVkLXVqYXFMRmtNIn0sImF1dGhvcml6YXRpb24iOiJhYyJ9.MEYCIQDZAGTcudcWFHZiUkr8jgF0cbBKT-C5H8jUSwh5fplCrwIhAMRR375Bm0DjmCt9P_85Q79ovtv7o97cvc1NOQaNWdrA"
	)

	response := Response{
		SessionIdentifier: loginTesting.AuthenticationId,
		RefreshURL:        dbsc_register_endpoint_config.DefaultRefreshPath,
		Scope: Scope{
			Origin:      fmt.Sprintf("https://%s", loginTesting.RegisteredDomain),
			IncludeSite: true,
		},
		Credentials: []*Credential{
			{
				Type:       "cookie",
				Name:       defaultAuthorizationRequestParser.JwtExtractor.TokenExtractor.Name,
				Attributes: session_cookie.Attributes(loginTesting.RegisteredDomain),
			},
		},
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json marshal (response): %v", err)
	}

	testCases := []struct {
		name           string
		args           *muxTesting.Args
		emptyPublicKey bool
	}{
		{
			name: "valid session response token happy path",
			args: &muxTesting.Args{
				Headers:            [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       responseData,
			},
		},
		{
			name: "invalid session response token",
			args: &muxTesting.Args{
				Headers:               [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, "invalid"}},
				ExpectedStatusCode:    http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{Detail: "Invalid token."},
			},
		},
		{
			name: "missing session response token",
			args: &muxTesting.Args{
				Headers:            [][2]string{{"Cookie", defaultSessionCookieString}},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Missing header.",
					Extension: map[string]any{
						"header": session.DbscSessionResponseHeaderName,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			testEndpointProcessor, err := dbsc_session_response_processor.New(
				"https://example.com"+dbsc_register_endpoint_config.DefaultPath,
				db,
				dbsc_session_response_processor_config.WithPopDbscChallenge(
					func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error) {
						if authenticationId != loginTesting.AuthenticationId {
							return nil, fmt.Errorf("authentication id mismatch: got %s, want %s", authenticationId, loginTesting.AuthenticationId)
						}

						expiresAt := time.Now().Add(time.Hour)
						return &dbsc_challenge.Challenge{
							Authentication: &authenticationPkg.Authentication{Id: authenticationId},
							Challenge:      []byte(challenge),
							ExpiresAt:      &expiresAt,
						}, nil
					},
				),
			)
			if err != nil {
				t.Fatalf("dbsc session response processor new: %v", err)
			}

			if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, testEndpointProcessor, loginTesting.RegisteredDomain); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			tc.args.Path = testEndpoint.Path
			tc.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, tc.args, httpServer.URL)
		})
	}
}

func TestEndpoint_Initialize(t *testing.T) {
	t.Parallel()

	type args struct {
		arp *authorizer_request_parser.Parser
		pr  *dbsc_session_response_processor.Processor
		dom string
	}

	arp, _, _ := loginTesting.SetUp()

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "nil authorizer parser", args: args{arp: nil, pr: defaultProcessor, dom: "example.com"}, wantErr: true},
		{name: "empty cookie name in parser", args: args{arp: &authorizer_request_parser.Parser{}, pr: defaultProcessor, dom: "example.com"}, wantErr: true},
		{name: "nil processor", args: args{arp: arp, pr: nil, dom: "example.com"}, wantErr: true},
		{name: "nil db in processor", args: args{arp: arp, pr: &dbsc_session_response_processor.Processor{}, dom: "example.com"}, wantErr: true},
		{name: "success", args: args{arp: arp, pr: defaultProcessor, dom: "example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := New().Initialize(tt.args.arp, tt.args.pr, tt.args.dom); (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	opts := []cmp.Option{
		cmpopts.IgnoreFields(
			Endpoint{},
			"updateAuthenticationWithDbscPublicKey",
		),
	}

	type args struct {
		options []dbsc_register_endpoint_config.Option
	}
	tests := []struct {
		name string
		args args
		want *Endpoint
	}{
		{
			name: "success, default args",
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:   dbsc_register_endpoint_config.DefaultPath,
						Method: http.MethodPost,
					},
				},
				RefreshPath: dbsc_refresh_endpoint_config.DefaultPath,
			},
		},
		{
			name: "success, custom path",
			args: args{options: []dbsc_register_endpoint_config.Option{dbsc_register_endpoint_config.WithPath("/test")}},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:   "/test",
						Method: http.MethodPost,
					},
				},
				RefreshPath: dbsc_refresh_endpoint_config.DefaultPath,
			},
		},
		{
			name: "success, custom refresh path",
			args: args{options: []dbsc_register_endpoint_config.Option{dbsc_register_endpoint_config.WithRefreshPath("/refresh-test")}},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:   dbsc_register_endpoint_config.DefaultPath,
						Method: http.MethodPost,
					},
				},
				RefreshPath: "/refresh-test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New(tt.args.options...)
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("endpoint mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}
