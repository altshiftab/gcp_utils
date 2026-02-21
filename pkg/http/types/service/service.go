package service

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelMux "github.com/Motmedel/utils_go/pkg/http/mux"
	gcpUtilsHttp "github.com/altshiftab/gcp_utils/pkg/http"
	"github.com/altshiftab/gcp_utils/pkg/http/types/service/service_config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type Service struct {
	Server *http.Server
	Mux    *motmedelMux.Mux
}

func New(domain string, port string, options ...service_config.Option) (*Service, error) {
	if domain == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("domain"))
	}

	if port == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("port"))
	}

	var scheme string
	if domain == "localhost" {
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

	var handler http.Handler
	if strings.EqualFold(domain, "localhost") {
		handler = vhostMux
	} else {
		handler = h2c.NewHandler(vhostMux, &http2.Server{})
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &Service{Server: httpServer, Mux: mux}, nil
}
