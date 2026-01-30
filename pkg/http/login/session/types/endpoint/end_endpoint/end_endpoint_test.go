package end_endpoint

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/end_endpoint/end_endpoint_config"
	loginTesting "github.com/altshiftab/gcp_utils/pkg/http/login/testing"
)

var httpServer *httptest.Server
var testEndpoint = New()
var testDb *sql.DB
var method motmedelCryptoInterfaces.Method

func TestMain(m *testing.M) {
	var authorizerRequestParser *authorizer_request_parser.Parser
	authorizerRequestParser, method, testDb = loginTesting.SetUp()

	if err := testEndpoint.Initialize(authorizerRequestParser, testDb); err != nil {
		panic(fmt.Errorf("test endpoint initialize: %w", err))
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)

	httpServer = httptest.NewServer(mux)

	code := m.Run()
	httpServer.Close()
	if testDb != nil {
		_ = testDb.Close()
	}

	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	authenticationIdCookie := loginTesting.MakeCookie("authentication-id", method)
	emptyAuthenticationIdToken := loginTesting.MakeCookie("", method)

	testCases := []struct {
		name string
		args *muxTesting.Args
	}{
		{
			name: "unauthenticated (no cookie)",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusUnauthorized,
			},
		},
		{
			name: "authenticated",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{"Cookie", authenticationIdCookie},
				},
				ExpectedStatusCode: http.StatusNoContent,
			},
		},
		{
			name: "authenticated with empty authentication id",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{"Cookie", emptyAuthenticationIdToken},
				},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Missing authentication id in the session token.",
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testCase.args.Path = testEndpoint.Path
			testCase.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}

}

// TestEndpoint_DbError spins up a dedicated server with a closed DB to hit the
// database error path in the handler and assert a 5xx response.
func TestEndpoint_DbError(t *testing.T) {
	t.Parallel()

	// Fresh setup to avoid affecting the shared TestMain server/DB.
	arp, signer, db := loginTesting.SetUp()
	ep := New()
	if err := ep.Initialize(arp, db); err != nil {
		t.Fatalf("endpoint initialize: %v", err)
	}

	// Close the DB to force an execution error on update.
	_ = db.Close()

	mux := &muxPkg.Mux{}
	mux.Add(ep.Endpoint.Endpoint)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Make a valid cookie to reach the DB update call.
	cookie := loginTesting.MakeCookie("auth-for-db-error", signer)

	args := &muxTesting.Args{
		Path:   ep.Path,
		Method: ep.Method,
		Headers: [][2]string{
			{"Cookie", cookie},
		},
		ExpectedStatusCode: http.StatusInternalServerError,
		ExpectedProblemDetail: &problem_detail.Detail{
			Title: "Internal Server Error",
		},
	}

	muxTesting.TestArgs(t, args, srv.URL)
}

func TestEndpoint_Initialize(t *testing.T) {
	t.Parallel()

	type args struct {
		authorizerRequestParser *authorizer_request_parser.Parser
		db                      *sql.DB
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty authorizer request parser",
			args: args{
				authorizerRequestParser: nil,
				db:                      testDb,
			},
			wantErr: true,
		},
		{
			name: "empty db",
			args: args{
				authorizerRequestParser: &authorizer_request_parser.Parser{},
				db:                      nil,
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				authorizerRequestParser: &authorizer_request_parser.Parser{},
				db:                      testDb,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := New().Initialize(tt.args.authorizerRequestParser, tt.args.db); (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	type args struct {
		options []end_endpoint_config.Option
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
						Path:       end_endpoint_config.DefaultPath,
						Method:     http.MethodPost,
						BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
					},
				},
			},
		},
		{
			name: "success, args",
			args: args{
				[]end_endpoint_config.Option{end_endpoint_config.WithPath("/test")},
			},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:       "/test",
						Method:     http.MethodPost,
						BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.options...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}
