package service

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
)

// get performs a request the linters accept: with a context, and closing the
// body.
func get(t *testing.T, url string) (string, error) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	if response == nil {
		return "", nil_error.New("response")
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("body close: %v", err)
		}
	}()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// newTestService serves a handler on a port of its own.
func newTestService(t *testing.T, handler http.Handler, shutdownTimeout time.Duration) (*Service, string) {
	t.Helper()

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net listen: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("listener close: %v", err)
	}

	return &Service{
		Server:          &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: time.Second},
		shutdownTimeout: shutdownTimeout,
	}, address
}

func TestServeFinishesRequestsBeingHandled(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})

	service, address := newTestService(
		t,
		http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
			close(started)
			<-release
			if _, err := responseWriter.Write([]byte("finished")); err != nil {
				t.Errorf("response writer write: %v", err)
			}
		}),
		5*time.Second,
	)

	stop := make(chan os.Signal, 1)
	served := make(chan error, 1)
	go func() { served <- service.serve(stop) }()

	responses := make(chan string, 1)
	go func() {
		body, err := get(t, "http://"+address)
		if err != nil {
			responses <- "error: " + err.Error()
			return
		}
		responses <- body
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the request was never handled")
	}

	// Asking the process to stop while a request is in flight must not end it.
	stop <- syscall.SIGTERM
	close(release)

	select {
	case body := <-responses:
		if body != "finished" {
			t.Errorf("response: got %q, want %q", body, "finished")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request never finished")
	}

	select {
	case err := <-served:
		if err != nil {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serving never stopped")
	}
}

func TestServeStopsAcceptingAfterBeingAskedToStop(t *testing.T) {
	t.Parallel()

	service, address := newTestService(
		t,
		http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
			responseWriter.WriteHeader(http.StatusNoContent)
		}),
		time.Second,
	)

	stop := make(chan os.Signal, 1)
	served := make(chan error, 1)
	go func() { served <- service.serve(stop) }()

	// Wait for the server to be listening.
	var err error
	for range 50 {
		if _, err = get(t, "http://"+address); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	stop <- syscall.SIGTERM

	select {
	case err := <-served:
		if err != nil {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serving never stopped")
	}

	if _, err := get(t, "http://"+address); err == nil {
		t.Error("the server still accepts requests")
	}
}

func TestServeReportsListenErrors(t *testing.T) {
	t.Parallel()

	service := &Service{Server: &http.Server{Addr: "127.0.0.1:1", ReadHeaderTimeout: time.Second}}

	err := service.serve(make(chan os.Signal, 1))
	if err == nil {
		t.Fatal("serve: got no error, want one")
	}
	if errors.Is(err, http.ErrServerClosed) {
		t.Errorf("serve: got %v", err)
	}
}

func TestServeWithoutServer(t *testing.T) {
	t.Parallel()

	service := &Service{}

	if err := service.serve(make(chan os.Signal, 1)); err == nil {
		t.Error("serve: got no error, want one")
	}
}
