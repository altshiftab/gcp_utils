package service

import (
	"net"
	"net/http"
	"testing"
)

func startService(t *testing.T, domain string) string {
	t.Helper()

	testService, err := New(domain, "0")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if testService == nil || testService.Server == nil {
		t.Fatalf("nil service or server")
	}

	listenConfig := &net.ListenConfig{}
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net listen: %v", err)
	}

	go func() {
		_ = testService.Server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = testService.Server.Close()
	})

	return listener.Addr().String()
}

func requestProto(t *testing.T, client *http.Client, address string, host string) string {
	t.Helper()

	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://"+address+"/",
		nil,
	)
	if err != nil {
		t.Fatalf("http new request: %v", err)
	}
	request.Host = host

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	if response == nil {
		t.Fatalf("nil response")
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("response body close: %v", err)
		}
	}()

	return response.Proto
}

// TestNewServesPriorKnowledgeH2c verifies that a non-localhost service serves both
// prior-knowledge unencrypted HTTP/2 — as GCP load balancers speak to their backends — and
// HTTP/1.1, on the same port.
func TestNewServesPriorKnowledgeH2c(t *testing.T) {
	t.Parallel()

	address := startService(t, "example.com")

	h2cProtocols := new(http.Protocols)
	h2cProtocols.SetUnencryptedHTTP2(true)
	h2cClient := &http.Client{Transport: &http.Transport{Protocols: h2cProtocols}}

	if proto := requestProto(t, h2cClient, address, "example.com"); proto != "HTTP/2.0" {
		t.Errorf("h2c proto: got %q, want HTTP/2.0", proto)
	}

	http1Client := &http.Client{Transport: &http.Transport{}}
	if proto := requestProto(t, http1Client, address, "example.com"); proto != "HTTP/1.1" {
		t.Errorf("http/1.1 proto: got %q, want HTTP/1.1", proto)
	}
}

func TestNewLocalhostServesHttp1(t *testing.T) {
	t.Parallel()

	address := startService(t, "localhost")

	http1Client := &http.Client{Transport: &http.Transport{}}
	if proto := requestProto(t, http1Client, address, "localhost"); proto != "HTTP/1.1" {
		t.Errorf("http/1.1 proto: got %q, want HTTP/1.1", proto)
	}
}
