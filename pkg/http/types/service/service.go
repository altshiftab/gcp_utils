package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelMux "github.com/Motmedel/utils_go/pkg/http/mux"
	gcpUtilsHttp "github.com/altshiftab/gcp_utils/pkg/http"
	"github.com/altshiftab/gcp_utils/pkg/http/types/service/service_config"
)

type Service struct {
	Server *http.Server
	Mux    *motmedelMux.Mux

	shutdownTimeout time.Duration
}

// Serve serves until the process is asked to stop, and then lets the requests
// it is handling finish. An instance is terminated whenever a revision is
// replaced or the service scales in, and a request killed midway leaves
// whatever it was doing half done, so the signal is handled rather than left to
// end the process.
func (s *Service) Serve() error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)

	return s.serve(signals)
}

func (s *Service) serve(stop <-chan os.Signal) error {
	server := s.Server
	if server == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("http server"))
	}

	served := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			served <- motmedelErrors.NewWithTrace(fmt.Errorf("http server listen and serve: %w", err))
			return
		}
		served <- nil
	}()

	select {
	case err := <-served:
		return err
	case <-stop:
	}

	shutdownTimeout := s.shutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = service_config.DefaultShutdownTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Requests still being handled are given the remaining time; those that do
	// not finish are ended when the process is killed anyway.
	if err := server.Shutdown(ctx); err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("http server shutdown: %w", err))
	}

	return nil
}

func New(domain string, port string, options ...service_config.Option) (*Service, error) {
	if domain == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("domain"))
	}

	if port == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("port"))
	}

	var scheme string
	if gcpUtilsHttp.IsLocalhost(domain) {
		scheme = "http"
	} else {
		scheme = "https"
	}

	baseUrl := &url.URL{Scheme: scheme, Host: domain}

	config := service_config.New(options...)

	mux := motmedelMux.New(config.StaticContentEndpoints...)
	if mux == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("mux"))
	}

	if err := gcpUtilsHttp.PatchMux(mux); err != nil {
		return nil, motmedelErrors.New(fmt.Errorf("patch mux: %w", err), baseUrl)
	}

	if config.Public {
		if err := gcpUtilsHttp.PatchPublicHttpServiceMux(mux, baseUrl); err != nil {
			return nil, motmedelErrors.New(fmt.Errorf("patch public http service mux: %w", err), baseUrl)
		}
	} else {
		if err := gcpUtilsHttp.PatchHttpServiceMux(mux, baseUrl); err != nil {
			return nil, motmedelErrors.New(fmt.Errorf("patch http service mux: %w", err), baseUrl)
		}
	}

	hostToSpecification := map[string]*motmedelMux.VhostMuxSpecification{domain: {Mux: mux}}

	for _, redirect := range config.Redirects {
		hostToSpecification[redirect[0]] = &motmedelMux.VhostMuxSpecification{RedirectTo: redirect[1]}
	}

	vhostMux := &motmedelMux.VhostMux{HostToSpecification: hostToSpecification}
	vhostMux.DefaultHeaders = mux.DefaultHeaders

	// GCP load balancers speak prior-knowledge unencrypted HTTP/2 to the backend, which the
	// standard library serves natively alongside HTTP/1; enabling both is harmless to plain
	// HTTP/1.1 clients (e.g. on localhost).
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	httpServer := &http.Server{
		Addr:                         fmt.Sprintf(":%s", port),
		Handler:                      vhostMux,
		Protocols:                    protocols,
		ReadHeaderTimeout:            5 * time.Second,
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}

	return &Service{Server: httpServer, Mux: mux, shutdownTimeout: config.ShutdownTimeout}, nil
}
