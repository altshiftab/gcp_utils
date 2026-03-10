package id_token_endpoint

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	motmedelCryptoEcdsa "github.com/Motmedel/utils_go/pkg/crypto/ecdsa"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	motmedelTestingCmp "github.com/Motmedel/utils_go/pkg/testing/cmp"
	"github.com/altshiftab/gcp_utils/pkg/http/login/session/types/session_manager"
	ssoTesting "github.com/altshiftab/gcp_utils/pkg/http/login/sso/testing"
)

const (
	defaultPath = "/id-token"
)

var sessionManager *session_manager.Manager
var idTokenAuthenticator *authenticator.AuthenticatorWithKeyHandler
var idTokenMethod *motmedelCryptoEcdsa.Method

func TestMain(m *testing.M) {
	sessionManager, idTokenAuthenticator, _, idTokenMethod = ssoTesting.SetUp()

	code := m.Run()
	_ = sessionManager.Db.Close()

	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                   string
		args                   *muxTesting.Args
		invalidIdToken         bool
		unverifiedEmailAddress bool
		emptyEmailAddress      bool
		skipIdToken            bool
	}{
		{
			name: "success",
			args: &muxTesting.Args{
				ExpectedStatusCode:     http.StatusNoContent,
				ExpectedHeadersPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "skip id token",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail:    "Missing token header.",
					Extension: map[string]any{"header": "Authorization"},
				},
			},
			skipIdToken: true,
		},
		{
			name: "invalid id token",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Invalid id token.",
				},
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

			testEndpoint, err := New[*ssoTesting.ProviderClaims](defaultPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			if err := testEndpoint.Initialize(idTokenAuthenticator, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			var tokenString string

			if !testCase.skipIdToken {
				if testCase.invalidIdToken {
					tokenString = "[]"
				} else {
					tokenPayload := map[string]any{
						"iss":      "aux",
						"aud":      "test-client",
						"iat":      time.Now().Add(-1 * time.Minute).Unix(),
						"nbf":      time.Now().Add(-1 * time.Minute).Unix(),
						"exp":      time.Now().Add(10 * time.Minute).Unix(),
						"verified": !testCase.unverifiedEmailAddress,
					}

					var tokenEmailAddress string
					if !testCase.emptyEmailAddress {
						tokenEmailAddress = ssoTesting.EmailAddress
					}
					tokenPayload["email_address"] = tokenEmailAddress

					token := motmedelJwtToken.Token{
						Header: map[string]any{
							"typ": "JWT",
							"kid": ssoTesting.KeyId,
						},
						Payload: tokenPayload,
					}
					tokenString, err = token.Encode(idTokenMethod)
					if err != nil {
						t.Fatalf("token encode: %v", err)
					}
				}
			}

			testCase.args.Path = testEndpoint.Path
			testCase.args.Method = testEndpoint.Method
			if !testCase.skipIdToken {
				testCase.args.Headers = append(
					testCase.args.Headers,
					[2]string{"Authorization", fmt.Sprintf("Bearer %s", tokenString)},
				)
			}

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}
}

func TestInitialize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                 string
		idTokenAuthenticator *authenticator.AuthenticatorWithKeyHandler
		sessionManager       *session_manager.Manager
		wantErr              error
	}{
		{
			name:                 "valid arguments",
			idTokenAuthenticator: idTokenAuthenticator,
			sessionManager:       sessionManager,
		},
		{
			name:                 "nil id token authenticator",
			idTokenAuthenticator: nil,
			sessionManager:       sessionManager,
			wantErr:              nil_error.New("id token authenticator"),
		},
		{
			name:                 "nil session manager",
			idTokenAuthenticator: idTokenAuthenticator,
			sessionManager:       nil,
			wantErr:              nil_error.New("session manager"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New[*ssoTesting.ProviderClaims](defaultPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			err = testEndpoint.Initialize(testCase.idTokenAuthenticator, testCase.sessionManager)
			motmedelTestingCmp.CompareErr(t, err, testCase.wantErr)
		})
	}
}

// TODO: Implement tests
//	- New()
//	- Provider claims unmarshal
//	- Create session error
