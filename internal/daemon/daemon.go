package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/crypto"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/metrics"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/utils"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/version"
)

// New wires the daemon services for one loaded configuration.
func New(ctx context.Context, logger *slog.Logger, conf *config.Config, tokenStorage tokenstorage.Storage) (*Runtime, error) {
	var appMetrics *metrics.Metrics
	if conf.Debug.Metrics {
		appMetrics = metrics.New(version.Version, version.Commit)
	}

	openvpnClient, httpHandler, err := setupOpenVPNClient(ctx, logger, conf, tokenStorage, appMetrics)
	if err != nil {
		return nil, fmt.Errorf("error setting up openvpn client: %w", err)
	}

	if conf.SSF.Enabled {
		logger.LogAttrs(ctx, slog.LevelWarn, "ssf.enabled is set, but the SSF receiver is not implemented yet; no events are received")
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

	if conf.Debug.Pprof || conf.Debug.Metrics {
		debugServer := newDebugServer(logger, conf, appMetrics)
		services = append(services, service{
			errPrefix: "error debug http listener",
			run:       debugServer.Listen,
		})
	}

	return newRuntime(logger, server, services), nil
}

func newDebugServer(logger *slog.Logger, conf *config.Config, appMetrics *metrics.Metrics) *httpserver.Server {
	return httpserver.NewHTTPServer(httpserver.ServerNameDebug, logger, config.HTTP{Listen: conf.Debug.Listen}, newDebugMux(conf, appMetrics))
}

// newDebugMux serves the profiling endpoints when debug.pprof is enabled
// and /metrics when appMetrics is not nil.
func newDebugMux(conf *config.Config, appMetrics *metrics.Metrics) *http.ServeMux {
	mux := http.NewServeMux()

	if conf.Debug.Pprof {
		mux.Handle("GET /", http.RedirectHandler("/debug/pprof/", http.StatusTemporaryRedirect))
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	}

	if appMetrics != nil {
		mux.Handle("GET /metrics", appMetrics)
	}

	return mux
}

func setupOpenVPNClient(
	ctx context.Context, logger *slog.Logger, conf *config.Config, tokenStorage tokenstorage.Storage, appMetrics *metrics.Metrics,
) (*openvpn.Client, *http.ServeMux, error) {
	httpClient := utils.NewOAuth2HTTPClient(nil)

	provider, err := providers.New(ctx, conf, httpClient)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating oauth2 provider: %w", err)
	}

	openvpnClient := openvpn.New(logger, conf, appMetrics)

	stateCrypto, err := crypto.NewWithMaxAge(conf.HTTP.Secret.String(), conf.OpenVPN.AuthPendingTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("create state cipher: %w", err)
	}

	oAuth2Client, err := oauth2.New(ctx, logger, conf, httpClient, tokenStorage, stateCrypto, provider, openvpnClient, appMetrics)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating oauth2 client: %w", err)
	}

	openvpnClient.SetOAuth2Client(oAuth2Client)

	return openvpnClient, httphandler.New(conf, oAuth2Client, openvpnClient.Ready), nil
}
