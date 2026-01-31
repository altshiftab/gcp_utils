package callback_endpoint

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/altshiftab/gcp_utils/pkg/http/login/database/types/oauth_flow"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	testing2 "github.com/altshiftab/gcp_utils/pkg/http/login/sso/testing"
	"golang.org/x/oauth2"
)

const (
	defaultPath = "/callback"
)

var sessionManager *session_manager.Manager
var idTokenAuthenticator *authenticator.AuthenticatorWithKeyHandler
var oauthConfig *oauth2.Config

func TestMain(m *testing.M) {
	sessionManager, idTokenAuthenticator, oauthConfig, _ = testing2.SetUp()

	code := m.Run()
	_ = sessionManager.Db.Close()

	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                   string
		args                   *muxTesting.Args
		oauthError             bool
		skipIdToken            bool
		invalidIdToken         bool
		skipCallbackCookie     bool
		emptyCallbackCookie    bool
		dbErr                  error
		noDbOauthFlow          bool
		nilDbOauthFlow         bool
		expiredOauthFlow       bool
		stateMismatch          bool
		unverifiedEmailAddress bool
		emptyEmailAddress      bool
	}{
		{
			name: "success",
			args: &muxTesting.Args{
				ExpectedStatusCode:     http.StatusSeeOther,
				ExpectedHeaders:        [][2]string{{"Location", testing2.RedirectUrl}},
				ExpectedHeadersPresent: []string{"Set-Cookie", "Sec-Session-Registration"},
			},
		},
		{
			name: "no callback cookie",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "No callback cookie.",
				},
			},
			skipCallbackCookie: true,
		},
		{
			name: "empty callback cookie",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Empty callback cookie.",
				},
			},
			emptyCallbackCookie: true,
		},
		{
			name: "no db oauth flow",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "No OAuth flow matches the callback cookie value.",
				},
			},
			noDbOauthFlow: true,
		},
		{
			name: "nil db oauth flow",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			nilDbOauthFlow: true,
		},
		{
			name: "db error",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			dbErr: fmt.Errorf("db error"),
		},
		{
			name: "expired oauth flow",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The OAuth flow has expired.",
				},
			},
			expiredOauthFlow: true,
		},
		{
			name: "state mismatch",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The OAuth flow state and url state do not match.",
				},
			},
			stateMismatch: true,
		},
		{
			name: "oauth error",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			oauthError: true,
		},
		{
			name: "skip id token",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			skipIdToken: true,
		},
		{
			name: "invalid id token",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			invalidIdToken: true,
		},
		{
			name: "unverified email address",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusForbidden,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The email address that is tied to the id token is unverified or invalid.",
				},
			},
			unverifiedEmailAddress: true,
		},
		{
			name: "empty email address",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			emptyEmailAddress: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New[*testing2.ProviderClaims](defaultPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			if err := testEndpoint.Initialize(oauthConfig, idTokenAuthenticator, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			testEndpoint.popOauthFlow = func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error) {
				if id != testing2.OauthFlowId {
					t.Fatalf("expected oauth flow id to match: got %s, want %s", id, testing2.OauthFlowId)
				}

				if testCase.dbErr != nil {
					return nil, testCase.dbErr
				}

				if testCase.noDbOauthFlow {
					return nil, sql.ErrNoRows
				}

				if testCase.nilDbOauthFlow {
					return nil, nil
				}

				flow := &oauth_flow.Flow{Id: testing2.OauthFlowId, RedirectUrl: testing2.RedirectUrl}

				if testCase.expiredOauthFlow {
					expiresAt := time.Now().Add(-1 * time.Hour)
					flow.ExpiresAt = &expiresAt
				} else {
					expiresAt := time.Now().Add(time.Hour)
					flow.ExpiresAt = &expiresAt
				}

				if testCase.stateMismatch {
					flow.State = "invalid_state"
				} else {
					flow.State = testing2.State
				}

				return flow, nil
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			var caseCode string
			if testCase.oauthError {
				caseCode = testing2.OauthErrorCode
			} else if testCase.skipIdToken {
				caseCode = testing2.OauthSkipIdTokenCode
			} else if testCase.invalidIdToken {
				caseCode = testing2.OauthInvalidIdTokenCode
			} else if testCase.unverifiedEmailAddress {
				caseCode = testing2.OauthUnverifiedEmailAddressCode
			} else if testCase.emptyEmailAddress {
				caseCode = testing2.OauthEmptyEmailAddressCode
			} else {
				caseCode = testing2.OauthCode
			}

			if !testCase.skipCallbackCookie {
				callbackCookie := http.Cookie{Name: testEndpoint.CallbackCookieName}
				if !testCase.emptyCallbackCookie {
					callbackCookie.Value = testing2.OauthFlowId
				}

				testCase.args.Headers = append(
					testCase.args.Headers,
					[2]string{"Cookie", callbackCookie.String()},
				)
			}

			testCase.args.Path = testEndpoint.Path + "?state=" + testing2.State + "&code=" + caseCode
			testCase.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}
}
