package refresh_endpoint

import (
	"context"
	"database/sql"
	"errors"
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
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/numeric_date"
	authenticationPkg "github.com/altshiftab/gcp_utils/pkg/http/login/database/types/authentication"
	loginTesting "github.com/altshiftab/gcp_utils/pkg/http/login/session/testing"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authentication_method"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/authorizer_request_parser"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/endpoint/refresh_endpoint/refresh_endpoint_config"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_token"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var defaultAuthorizationRequestParser *authorizer_request_parser.Parser

var db *sql.DB
var method motmedelCryptoInterfaces.Method
var sessionManager *session_manager.Manager

func TestMain(m *testing.M) {
	defaultAuthorizationRequestParser, method, db = loginTesting.SetUp()

	var err error
	sessionManager, err = session_manager.New(method, db, loginTesting.Issuer, loginTesting.RegisteredDomain)
	if err != nil {
		panic(fmt.Errorf("session manager new: %w", err))
	}

	code := m.Run()
	if db != nil {
		_ = db.Close()
	}

	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                      string
		args                      *muxTesting.Args
		noDbAuthentication        bool
		hasPublicKey              bool
		dbErr                     error
		nilDbAuthentication       bool
		nilSessionToken           bool
		invalidSessionTokenClaims bool
		invalidSessionTokenExp    bool
		invalidSessionTokenNbf    bool
		negativeDuration          bool
	}{
		{
			name: "ext session happy path refresh",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeCookieExplicit(
							loginTesting.AuthenticationId,
							method,
							[]string{authentication_method.Sso},
							time.Now().Add(1*time.Hour),
							time.Now().Add(-1*99*time.Hour),
						),
					},
				},
				ExpectedStatusCode:     http.StatusNoContent,
				ExpectedHeadersPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "ext session happy path no refresh",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeCookieExplicit(
							loginTesting.AuthenticationId,
							method,
							[]string{authentication_method.Sso},
							time.Now().Add(99*time.Hour),
							time.Now(),
						),
					},
				},
				ExpectedStatusCode:        http.StatusNoContent,
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "ext session public key",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeStandardCookie(loginTesting.AuthenticationId, method),
					},
				},
				ExpectedStatusCode:        http.StatusNoContent,
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			hasPublicKey: true,
		},
		{
			name: "hwk session happy path",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeCookieExplicit(
							loginTesting.AuthenticationId,
							method,
							[]string{authentication_method.Dbsc},
							time.Now().Add(1*time.Hour),
							time.Now().Add(-1*99*time.Hour),
						),
					},
				},
				ExpectedStatusCode:        http.StatusNoContent,
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "db error",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeStandardCookie(loginTesting.AuthenticationId, method),
					},
				},
				ExpectedStatusCode:        http.StatusInternalServerError,
				ExpectedProblemDetail:     &problem_detail.Detail{},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			dbErr: errors.New("db error"),
		},
		{
			name: "nil db authentication",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeStandardCookie(loginTesting.AuthenticationId, method),
					},
				},
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			nilDbAuthentication: true,
		},
		{
			name: "empty authentication id",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeCookieExplicit(
							"",
							method,
							[]string{authentication_method.Sso},
							time.Now().Add(1*time.Hour),
							time.Now().Add(-1*99*time.Hour),
						),
					},
				},
				ExpectedStatusCode:        http.StatusBadRequest,
				ExpectedProblemDetail:     &problem_detail.Detail{Detail: "The session token authentication id is empty."},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "nil session token",
			args: &muxTesting.Args{
				ExpectedStatusCode:        http.StatusInternalServerError,
				ExpectedProblemDetail:     &problem_detail.Detail{},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			nilSessionToken: true,
		},
		{
			name: "invalid session token claims",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The session token claims are empty.",
				},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			invalidSessionTokenClaims: true,
		},
		{
			name: "invalid session token exp",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The session token expires at is empty.",
				},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			invalidSessionTokenExp: true,
		},
		{
			name: "invalid session token exp",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The session token not before is empty.",
				},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			invalidSessionTokenNbf: true,
		},
		{
			name: "session negative duration",
			args: &muxTesting.Args{
				ExpectedStatusCode:        http.StatusBadRequest,
				ExpectedProblemDetail:     &problem_detail.Detail{Detail: "The expiration duration is negative, indicating an invalid session token."},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			negativeDuration: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			testEndpoint.selectRefreshAuthentication = func(ctx context.Context, id string, db *sql.DB) (*authenticationPkg.Authentication, error) {
				if id != loginTesting.AuthenticationId {
					t.Fatalf("expected id and authentication id to match: got %s, want %s", id, loginTesting.AuthenticationId)
				}

				if testCase.dbErr != nil {
					return nil, testCase.dbErr
				}

				if testCase.noDbAuthentication {
					return nil, sql.ErrNoRows
				}

				if testCase.nilDbAuthentication {
					return nil, nil
				}

				expiresAt := time.Now().Add(time.Hour)
				authentication := &authenticationPkg.Authentication{
					Id:        id,
					Ended:     false,
					ExpiresAt: &expiresAt,
				}

				if testCase.hasPublicKey {
					authentication.DbscPublicKey = []byte{1, 2, 3}
				}

				return authentication, nil
			}

			if testCase.nilSessionToken || testCase.invalidSessionTokenClaims || testCase.invalidSessionTokenExp || testCase.invalidSessionTokenNbf || testCase.negativeDuration {
				if testCase.nilSessionToken {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return nil, nil
						},
					)
				} else if testCase.invalidSessionTokenClaims {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return &session_token.Token{
								AuthenticationId: loginTesting.AuthenticationId,
								Claims:           nil,
							}, nil
						},
					)
				} else if testCase.invalidSessionTokenExp {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return &session_token.Token{
								AuthenticationId: loginTesting.AuthenticationId,
								Claims: &session_claims.Claims{
									Claims: registered_claims.Claims{
										ExpiresAt: nil,
									},
								},
							}, nil
						},
					)
				} else if testCase.invalidSessionTokenNbf {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return &session_token.Token{
								AuthenticationId: loginTesting.AuthenticationId,
								Claims: &session_claims.Claims{
									Claims: registered_claims.Claims{
										ExpiresAt: numeric_date.New(time.Now().Add(time.Hour)),
										NotBefore: nil,
									},
								},
							}, nil
						},
					)
				} else if testCase.negativeDuration {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return &session_token.Token{
								AuthenticationId: loginTesting.AuthenticationId,
								Claims: &session_claims.Claims{
									Claims: registered_claims.Claims{
										ExpiresAt: numeric_date.New(time.Now().Add(-1 * time.Hour)),
										NotBefore: numeric_date.New(time.Now()),
									},
									AuthenticationMethods: []string{authentication_method.Sso},
								},
							}, nil
						},
					)
				} else {
					t.Fatalf("unexpected authentication parser replace case")
				}
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			testCase.args.Path = testEndpoint.Path
			testCase.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}

}

func TestEndpoint_Initialize(t *testing.T) {
	// Note: do NOT parallelize this test's sub-cases unless each case builds
	// fully isolated dependencies. We keep it sequential for determinism.

	type args struct {
		authorizerRequestParser *authorizer_request_parser.Parser
		sessionManager          *session_manager.Manager
	}

	// builder creates fresh, isolated dependencies per test case
	newDeps := func(t *testing.T) (arp *authorizer_request_parser.Parser, sm *session_manager.Manager, closeDb func()) {
		arp, m, localDb := loginTesting.SetUp()
		// ensure DB is closed per-case
		closeDb = func() {
			if localDb != nil {
				_ = localDb.Close()
			}
		}
		s, err := session_manager.New(m, localDb, loginTesting.Issuer, "example.com")
		if err != nil {
			t.Fatalf("session manager new: %v", err)
		}
		return arp, s, closeDb
	}

	// helper to deep-clone the parser and its nested extractors
	cloneParser := func(p *authorizer_request_parser.Parser) *authorizer_request_parser.Parser {
		if p == nil {
			return nil
		}
		cp := *p
		if p.JwtExtractor != nil {
			jwtCp := *p.JwtExtractor
			if jwtCp.TokenExtractor != nil {
				tokCp := *jwtCp.TokenExtractor
				jwtCp.TokenExtractor = &tokCp
			}
			cp.JwtExtractor = &jwtCp
		}
		return &cp
	}

	tests := []struct {
		name    string
		prepare func(t *testing.T) args
		wantErr bool
	}{
		{
			name: "success",
			prepare: func(t *testing.T) args {
				arp, sm, done := newDeps(t)
				t.Cleanup(done)
				return args{authorizerRequestParser: arp, sessionManager: sm}
			},
		},
		{
			name: "nil authorizer parser",
			prepare: func(t *testing.T) args {
				_, sm, done := newDeps(t)
				t.Cleanup(done)
				return args{authorizerRequestParser: nil, sessionManager: sm}
			},
			wantErr: true,
		},
		{
			name: "nil session manager",
			prepare: func(t *testing.T) args {
				arp, _, done := newDeps(t)
				t.Cleanup(done)
				return args{authorizerRequestParser: arp, sessionManager: nil}
			},
			wantErr: true,
		},
		{
			name: "nil session manager db",
			prepare: func(t *testing.T) args {
				arp, sm, done := newDeps(t)
				t.Cleanup(done)
				smCopy := *sm
				smCopy.Db = nil
				return args{authorizerRequestParser: arp, sessionManager: &smCopy}
			},
			wantErr: true,
		},
		{
			name: "nil jwt extractor",
			prepare: func(t *testing.T) args {
				arp, sm, done := newDeps(t)
				t.Cleanup(done)
				arpCp := cloneParser(arp)
				arpCp.JwtExtractor = nil
				return args{authorizerRequestParser: arpCp, sessionManager: sm}
			},
			wantErr: true,
		},
		{
			name: "nil jwt extractor token extractor",
			prepare: func(t *testing.T) args {
				arp, sm, done := newDeps(t)
				t.Cleanup(done)
				arpCp := cloneParser(arp)
				if arpCp.JwtExtractor != nil {
					jwtCp := *arpCp.JwtExtractor
					jwtCp.TokenExtractor = nil
					arpCp.JwtExtractor = &jwtCp
				}
				return args{authorizerRequestParser: arpCp, sessionManager: sm}
			},
			wantErr: true,
		},
		{
			name: "empty cookie name",
			prepare: func(t *testing.T) args {
				arp, sm, done := newDeps(t)
				t.Cleanup(done)
				arpCp := cloneParser(arp)
				if arpCp.JwtExtractor != nil && arpCp.JwtExtractor.TokenExtractor != nil {
					tok := *arpCp.JwtExtractor.TokenExtractor
					tok.Name = ""
					jwtCp := *arpCp.JwtExtractor
					jwtCp.TokenExtractor = &tok
					arpCp.JwtExtractor = &jwtCp
				}
				return args{authorizerRequestParser: arpCp, sessionManager: sm}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.prepare(t)
			if err := New().Initialize(a.authorizerRequestParser, a.sessionManager); (err != nil) != tt.wantErr {
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
			"selectRefreshAuthentication",
		),
	}

	type args struct {
		options []refresh_endpoint_config.Option
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
						Path:   refresh_endpoint_config.DefaultPath,
						Method: http.MethodPost,
					},
				},
				SessionDuration: refresh_endpoint_config.DefaultSessionDuration,
			},
		},
		{
			name: "success, custom path",
			args: args{options: []refresh_endpoint_config.Option{refresh_endpoint_config.WithPath("/test")}},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:   "/test",
						Method: http.MethodPost,
					},
				},
				SessionDuration: refresh_endpoint_config.DefaultSessionDuration,
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
