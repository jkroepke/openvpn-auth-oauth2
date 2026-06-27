package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/crypto"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

// New wires the daemon services for one loaded configuration.
func New(ctx context.Context, logger *slog.Logger, conf config.Config, tokenStorage tokenstorage.Storage) (*Runtime, error) {
	openvpnClient, httpHandler, err := setupOpenVPNClient(ctx, logger, conf, tokenStorage)
	if err != nil {
		return nil, fmt.Errorf("error setting up openvpn client: %w", err)
	}

	server := httpserver.NewHTTPServer(httpserver.ServerNameDefault, logger, conf.HTTP, httpHandler)
	services := []service{
		{
			errPrefix: "error http listener",
			run:       server.Listen,
		},
		{
			errPrefix: "openvpn",
			run:       openvpnClient.Connect,
		},
	}

	if conf.Debug.Pprof {
		debugServer := newDebugServer(logger, conf)
		services = append(services, service{
			errPrefix: "error debug http listener",
			run:       debugServer.Listen,
		})
	}

	return newRuntime(logger, server, services), nil
}

func newDebugServer(logger *slog.Logger, conf config.Config) *httpserver.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.RedirectHandler("/debug/pprof/", http.StatusTemporaryRedirect))
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)

	return httpserver.NewHTTPServer(httpserver.ServerNameDebug, logger, config.HTTP{Listen: conf.Debug.Listen}, mux)
}

func setupOpenVPNClient(
	ctx context.Context, logger *slog.Logger, conf config.Config, tokenStorage tokenstorage.Storage,
) (*openvpn.Client, *http.ServeMux, error) {
	httpClient := &http.Client{Transport: utils.NewUserAgentTransport(http.DefaultTransport)}

	provider, err := providers.New(ctx, conf, httpClient)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating oauth2 provider: %w", err)
	}

	openvpnClient := openvpn.New(logger, conf)
	stateCrypto := crypto.NewWithMaxAge(conf.HTTP.Secret.String(), conf.OpenVPN.AuthPendingTimeout)

	oAuth2Client, err := oauth2.New(ctx, logger, conf, httpClient, tokenStorage, stateCrypto, provider, openvpnClient)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating oauth2 client: %w", err)
	}

	openvpnClient.SetOAuth2Client(oAuth2Client)

	return openvpnClient, httphandler.New(conf, oAuth2Client), nil
}
