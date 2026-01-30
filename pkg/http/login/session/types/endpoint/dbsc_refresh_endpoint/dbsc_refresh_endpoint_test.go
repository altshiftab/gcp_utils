package dbsc_refresh_endpoint

import (
	"context"
	"database/sql"
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
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/google/go-cmp/cmp"
)

var defaultTestEndpoint = New()
var defaultHttpServer *httptest.Server
var defaultSessionCookieString string
var defaultAuthorizationRequestParser *authorizer_request_parser.Parser
var defaultProcessor *dbsc_session_response_processor.Processor

var db *sql.DB
var method motmedelCryptoInterfaces.Method
var sessionManager *session_manager.Manager

func TestMain(m *testing.M) {
	var err error

	defaultAuthorizationRequestParser, method, db = loginTesting.SetUp()
	sessionManager, err = session_manager.New(method, db, loginTesting.Issuer, loginTesting.RegisteredDomain)
	if err != nil {
		panic(fmt.Errorf("session manager new: %w", err))
	}

	defaultProcessor, err = dbsc_session_response_processor.New("https://example.com"+dbsc_register_endpoint_config.DefaultPath, db)
	if err != nil {
		panic(fmt.Errorf("dbsc session response processor new: %w", err))
	}

	if err := defaultTestEndpoint.Initialize(defaultAuthorizationRequestParser, defaultProcessor, sessionManager); err != nil {
		panic(fmt.Errorf("test endpoint initialize: %w", err))
	}

	mux := &muxPkg.Mux{}
	mux.Add(defaultTestEndpoint.Endpoint.Endpoint)
	defaultHttpServer = httptest.NewServer(mux)
	defer defaultHttpServer.Close()

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
		validToken    = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRic2Mrand0In0.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tL2FwaS9zZXNzaW9uL2Ric2MvcmVnaXN0ZXIiLCJqdGkiOiJjdiIsImlhdCI6MTcyNTU3OTA1NSwia2V5Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiSy1aSHM3cWo1RmtDZGhIeno4NFFzQ2FkOFFwVnNJdzVIRWdhQkZoeEN3TSIsInkiOiJwanUtWFVCdDN3TXhzRlBRdW9EVHNWcjU4SHREc2ZnOTVkLXVqYXFMRmtNIn0sImF1dGhvcml6YXRpb24iOiJhYyJ9.MEYCIQDZAGTcudcWFHZiUkr8jgF0cbBKT-C5H8jUSwh5fplCrwIhAMRR375Bm0DjmCt9P_85Q79ovtv7o97cvc1NOQaNWdrA"
		testChallenge = "test-challenge"
	)

	validTokenPublicKey := []byte{
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
		0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x2b, 0xe6, 0x47, 0xb3, 0xba,
		0xa3, 0xe4, 0x59, 0x02, 0x76, 0x11, 0xf3, 0xcf, 0xce, 0x10, 0xb0, 0x26, 0x9d, 0xf1, 0x0a, 0x55,
		0xb0, 0x8c, 0x39, 0x1c, 0x48, 0x1a, 0x04, 0x58, 0x71, 0x0b, 0x03, 0xa6, 0x3b, 0xbe, 0x5d, 0x40,
		0x6d, 0xdf, 0x03, 0x31, 0xb0, 0x53, 0xd0, 0xba, 0x80, 0xd3, 0xb1, 0x5a, 0xf9, 0xf0, 0x7b, 0x43,
		0xb1, 0xf8, 0x3d, 0xe5, 0xdf, 0xae, 0x8d, 0xaa, 0x8b, 0x16, 0x43,
	}

	testCases := []struct {
		name               string
		args               *muxTesting.Args
		noDbAuthentication bool
		emptyPublicKey     bool
		publicKeyMismatch  bool
	}{
		{
			name: "valid session response token happy path",
			args: &muxTesting.Args{
				Headers:            [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusNoContent,
			},
		},
		{
			name: "valid session response token, no db authentication",
			args: &muxTesting.Args{
				Headers:            [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "No authentication matches the authentication id.",
				},
			},
			noDbAuthentication: true,
		},
		{
			name: "valid session response token, empty public key",
			args: &muxTesting.Args{
				Headers:            [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "No public key for authentication.",
				},
			},
			emptyPublicKey: true,
		},
		{
			name: "valid session response token, public key mismatch",
			args: &muxTesting.Args{
				Headers:            [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Public key mismatch.",
				},
			},
			publicKeyMismatch: true,
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
			name: "multiple session response headers",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{"Cookie", defaultSessionCookieString},
					{"Sec-Session-Response", "val1"},
					{"Sec-Session-Response", "val2"},
				},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail:    "Multiple header values.",
					Extension: map[string]any{"header": session.DbscSessionResponseHeaderName},
				},
			},
		},
		{
			name: "no session response header happy path",
			args: &muxTesting.Args{
				Headers:            [][2]string{{"Cookie", defaultSessionCookieString}},
				ExpectedStatusCode: http.StatusUnauthorized,
				ExpectedHeaders: [][2]string{
					{session.DbscSessionChallengeHeaderName, fmt.Sprintf("\"%s\";id=\"%s\"", testChallenge, loginTesting.AuthenticationId)},
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

			if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, testEndpointProcessor, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			testEndpoint.selectRefreshAuthentication = func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error) {
				if id != loginTesting.AuthenticationId {
					t.Fatalf("expected id and authentication id to match: got %s, want %s", id, loginTesting.AuthenticationId)
				}

				if tc.noDbAuthentication {
					return nil, sql.ErrNoRows
				}

				publicKey := validTokenPublicKey
				if tc.emptyPublicKey {
					publicKey = nil
				}

				if tc.publicKeyMismatch {
					publicKey = []byte{1, 2, 3}
				}

				expiresAt := time.Now().Add(time.Hour)
				return &authenticationPkg.Authentication{
					Id:            id,
					Ended:         false,
					DbscPublicKey: publicKey,
					ExpiresAt:     &expiresAt,
				}, nil
			}

			testEndpoint.generateDbscChallenge = func() (string, error) {
				return testChallenge, nil
			}

			testEndpoint.insertDbscChallenge = func(ctx context.Context, challenge string, authenticationId string, challengeDuration time.Duration, db *sql.DB) error {
				if challenge != testChallenge {
					t.Fatalf("expected challenge to match: got %s, want %s", challenge, testChallenge)
				}

				if authenticationId != loginTesting.AuthenticationId {
					t.Fatalf("expected authentication id to match: got %s, want %s", authenticationId, loginTesting.AuthenticationId)
				}

				if challengeDuration != testEndpoint.ChallengeDuration {
					t.Fatalf("expected challenge duration to match: got %s, want %s", challengeDuration, testEndpoint.ChallengeDuration)
				}

				return nil
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
		sm  *session_manager.Manager
	}

	arp, _, _ := loginTesting.SetUp()
	sm, err := session_manager.New(method, db, loginTesting.Issuer, "example.com")
	if err != nil {
		t.Fatalf("session manager new: %v", err)
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "nil authorizer parser", args: args{arp: nil, pr: defaultProcessor, sm: sm}, wantErr: true},
		{name: "nil processor", args: args{arp: arp, pr: nil, sm: sm}, wantErr: true},
		{name: "nil session manager", args: args{arp: arp, pr: defaultProcessor, sm: nil}, wantErr: true},
		{name: "nil db in session manager", args: args{arp: arp, pr: defaultProcessor, sm: &session_manager.Manager{}}, wantErr: true},
		{name: "success", args: args{arp: arp, pr: defaultProcessor, sm: sm}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := New().Initialize(tt.args.arp, tt.args.pr, tt.args.sm); (err != nil) != tt.wantErr {
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
			"insertDbscChallenge",
			"generateDbscChallenge",
			"selectRefreshAuthentication",
		),
	}

	type args struct {
		options []dbsc_refresh_endpoint_config.Option
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
						Path:   dbsc_refresh_endpoint_config.DefaultPath,
						Method: http.MethodPost,
					},
				},
				SessionDuration:   dbsc_refresh_endpoint_config.DefaultSessionDuration,
				ChallengeDuration: dbsc_refresh_endpoint_config.DefaultChallengeDuration,
			},
		},
		{
			name: "success, custom path",
			args: args{options: []dbsc_refresh_endpoint_config.Option{dbsc_refresh_endpoint_config.WithPath("/test")}},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:   "/test",
						Method: http.MethodPost,
					},
				},
				SessionDuration:   dbsc_refresh_endpoint_config.DefaultSessionDuration,
				ChallengeDuration: dbsc_refresh_endpoint_config.DefaultChallengeDuration,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := New(tt.args.options...)
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("endpoint mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}
