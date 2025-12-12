package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	motmedelNetErrors "github.com/Motmedel/utils_go/pkg/net/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	authErrors "github.com/altshiftab/gcp_utils/pkg/auth/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	ErrStateMismatch = errors.New("state mismatch")
	ErrMissingCode   = errors.New("missing code")
)

const defaultCredentialsScope = "https://www.googleapis.com/auth/cloud-platform"

func TokenFromFilePath(ctx context.Context, path string) (*oauth2.Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if path == "" {
		return nil, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("os open: %w", err))
	}
	defer func() {
		if err := file.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithErrorContextValue(
					ctx,
					motmedelErrors.NewWithTrace(fmt.Errorf("file close: %w", err)),
				),
				"An error occurred when closing the file.",
			)
		}
	}()

	var token oauth2.Token
	if err := json.UnmarshalRead(file, &token); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("json unmarshal read: %w", err))
	}

	return &token, nil
}

// openBrowser tries to open the provided URL in the default browser.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default: // "linux", "freebsd", etc.
		return exec.Command("xdg-open", url).Start()
	}
}

func randomState(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "state-token"
	}
	return hex.EncodeToString(b)
}

func GetOauthTokenFromWeb(ctx context.Context, config *oauth2.Config) (*oauth2.Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if config == nil {
		// TODO: Use proper error.
		return nil, motmedelErrors.NewWithTrace(errors.New("nil config"))
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("net listen: %w", err))
	}
	if utils.IsNil(listener) {
		return nil, motmedelErrors.NewWithTrace(motmedelNetErrors.ErrNilListener)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithErrorContextValue(
					ctx,
					motmedelErrors.NewWithTrace(fmt.Errorf("listener close: %w", err)),
				),
				"An error occurred when closing the listener.",
			)
		}
	}()

	listenerAddr := listener.Addr()
	if utils.IsNil(listenerAddr) {
		return nil, motmedelErrors.NewWithTrace(motmedelNetErrors.ErrNilAddr)
	}

	tcpAddr, err := utils.ConvertToNonZero[*net.TCPAddr](listenerAddr)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("convert to non zero (listener addr): %w", err))
	}
	port := tcpAddr.Port

	// Copy the config and override the RedirectURL to match the chosen port.
	// Installed-app OAuth clients typically register `http://localhost`, which accepts any port.
	configCopy := *config
	configCopy.RedirectURL = fmt.Sprintf("http://localhost:%d/", port)

	// Create a random state to prevent CSRF
	state := randomState(16)

	// Build auth URL and open the browser
	authUrl := configCopy.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	fmt.Printf("Opening browser for authorization...\nIf it doesn't open, visit this URL:\n%v\n", authUrl)
	_ = openBrowser(authUrl)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		requestUrl := request.URL
		if requestUrl == nil {
			errCh <- motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequestUrl)
		}

		query := requestUrl.Query()
		if query == nil {
			errCh <- motmedelErrors.NewWithTrace(fmt.Errorf("%w (query)", motmedelErrors.ErrNilMap))
		}

		if query.Get("state") != state {
			http.Error(responseWriter, "State mismatch", http.StatusBadRequest)
			errCh <- motmedelErrors.NewWithTrace(ErrStateMismatch)
			return
		}

		code := query.Get("code")
		if code == "" {
			http.Error(responseWriter, "Missing code", http.StatusBadRequest)
			errCh <- motmedelErrors.NewWithTrace(ErrMissingCode)
			return
		}

		_, _ = fmt.Fprintln(responseWriter, "Authorization received. You may close this window and return to the app.")

		codeCh <- code
	})

	server := &http.Server{Handler: mux}
	defer func() {
		if err := server.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithErrorContextValue(
					ctx,
					motmedelErrors.NewWithTrace(fmt.Errorf("http server close: %w", err), server),
				),
				"An error occurred when closing the server.",
			)
		}
	}()

	go func() {
		if err := server.Serve(listener); err != nil {
			errCh <- motmedelErrors.NewWithTrace(fmt.Errorf("http server serve: %w", err), server)
		}
	}()

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("authorization failed: %w", err))
	case <-ctx.Done():
		return nil, fmt.Errorf("context done (waiting for code): %w", ctx.Err())
	}

	token, err := configCopy.Exchange(ctx, code)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("oauth2 config exchange: %w", err))
	}

	return token, nil
}

func GetDefaultCredentialsToken(ctx context.Context, scopes ...string) (*oauth2.Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if len(scopes) == 0 {
		scopes = []string{defaultCredentialsScope}
	}

	credentials, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("find default credentials: %w", err))
	}
	if credentials == nil {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrNilCredentials)
	}

	tokenSource := credentials.TokenSource
	if utils.IsNil(tokenSource) {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrNilTokenSource)
	}

	credentialsToken, err := tokenSource.Token()
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("token source token: %w", err))
	}

	return credentialsToken, nil
}

func makeOauthClient(
	ctx context.Context,
	accountKey []byte,
	impersonateEmailAddress string,
	scopes ...string,
) (*http.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(accountKey) == 0 {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrEmptyAccountKey)
	}

	accountKeyConfig, err := google.JWTConfigFromJSON(accountKey, scopes...)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("google jwt config from json: %w", err))
	}
	if accountKeyConfig == nil {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrNilAccountKeyConfig)
	}

	accountKeyConfig.Subject = impersonateEmailAddress

	tokenSource := accountKeyConfig.TokenSource(ctx)
	if utils.IsNil(tokenSource) {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrNilTokenSource)
	}

	accountKeyToken, err := tokenSource.Token()
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("jwt config token source: %w", err))
	}

	return oauth2.NewClient(ctx, oauth2.StaticTokenSource(accountKeyToken)), nil
}

func MakeOauthClientFromAccountKey(ctx context.Context, accountKey []byte, scopes ...string) (*http.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(accountKey) == 0 {
		return nil, nil
	}

	return makeOauthClient(ctx, accountKey, "", scopes...)
}

func MakeImpersonatedOauthClientFromAccountKey(
	ctx context.Context,
	accountKey []byte,
	impersonateEmailAddress string,
	scopes ...string,
) (*http.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if impersonateEmailAddress == "" {
		return nil, motmedelErrors.NewWithTrace(authErrors.ErrEmptyImpersonateEmailAddress)
	}

	if len(accountKey) == 0 {
		return nil, nil
	}

	return makeOauthClient(ctx, accountKey, impersonateEmailAddress, scopes...)
}
