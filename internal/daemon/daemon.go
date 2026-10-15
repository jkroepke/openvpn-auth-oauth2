package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"slices"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/crypto"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/metrics"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/revocation"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/utils"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/version"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	xoauth2 "golang.org/x/oauth2"
)

// New wires the daemon services for one loaded configuration.
// tokenStorage and sessions are shared across configuration reloads.
// reload is true for every configuration after the first one.
func New(
	ctx context.Context, logger *slog.Logger, conf *config.Config, tokenStorage tokenstorage.Storage, sessions *sessionregistry.Registry,
	reload bool,
) (*Runtime, error) {
	var appMetrics *metrics.Metrics
	if conf.Debug.Metrics {
		appMetrics = metrics.New(version.Version, version.Commit)
	}

	httpClient := utils.NewOAuth2HTTPClient(nil)

	openvpnClient, oAuth2Client, httpHandler, err := setupOpenVPNClient(ctx, logger, conf, httpClient, tokenStorage, sessions, appMetrics)
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

	if conf.SSF.Enabled {
		enforcer := revocation.New(logger, conf, sessions, oAuth2Client, openvpnClient, appMetrics)

		setup := func(ctx context.Context) (*ssf.Receiver, error) {
			return NewSSFReceiver(ctx, logger, conf, httpClient, oAuth2Client, enforcer, appMetrics)
		}

		run, err := ssfReceiverService(ctx, logger, conf, appMetrics, reload, setup)
		if err != nil {
			return nil, fmt.Errorf("error setting up SSF receiver: %w", err)
		}

		services = append(services, service{
			errPrefix: "ssf receiver",
			run:       run,
		})
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
	ctx context.Context, logger *slog.Logger, conf *config.Config, httpClient *http.Client,
	tokenStorage tokenstorage.Storage, sessions *sessionregistry.Registry, appMetrics *metrics.Metrics,
) (*openvpn.Client, *oauth2.Client, *http.ServeMux, error) {
	provider, err := providers.New(ctx, conf, httpClient)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating oauth2 provider: %w", err)
	}

	openvpnClient := openvpn.New(logger, conf, appMetrics)

	stateCrypto, err := crypto.NewWithMaxAge(conf.HTTP.Secret.String(), conf.OpenVPN.AuthPendingTimeout)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create state cipher: %w", err)
	}

	oAuth2Client, err := oauth2.New(ctx, logger, conf, httpClient, tokenStorage, stateCrypto, provider, openvpnClient, appMetrics)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating oauth2 client: %w", err)
	}

	oAuth2Client.SetSessionRegistry(sessions)
	openvpnClient.SetOAuth2Client(oAuth2Client)

	return openvpnClient, oAuth2Client, httphandler.New(conf, oAuth2Client, openvpnClient.Ready), nil
}

// NewSSFReceiver discovers the SSF transmitter of conf and returns a receiver
// that authenticates with ssf.poll.token, or with access tokens from the
// client credentials grant of oAuth2Client.
func NewSSFReceiver(
	ctx context.Context, logger *slog.Logger, conf *config.Config, httpClient *http.Client,
	oAuth2Client *oauth2.Client, handler ssf.Handler, appMetrics *metrics.Metrics,
) (*ssf.Receiver, error) {
	return setupSSFReceiver(ctx, logger, conf, httpClient, ssfTokenSource(conf, oAuth2Client), handler, appMetrics)
}

// ssfReceiverService returns the run function of the SSF receiver.
//
// At the first start, a discovery error stops the startup, so a
// misconfigured receiver is noticed at once. After a reload, a transmitter
// that is unreachable for a moment must not end the VPN logins, so discovery
// is retried in the background instead.
func ssfReceiverService(
	ctx context.Context, logger *slog.Logger, conf *config.Config, appMetrics *metrics.Metrics, reload bool,
	setup func(ctx context.Context) (*ssf.Receiver, error),
) (func(context.Context) error, error) {
	if !reload {
		receiver, err := setup(ctx)
		if err != nil {
			return nil, err
		}

		return receiver.Run, nil
	}

	return func(ctx context.Context) error {
		wait := conf.SSF.Poll.Interval

		for {
			receiver, err := setup(ctx)
			if err == nil {
				return receiver.Run(ctx)
			}

			if ctx.Err() != nil {
				return nil //nolint:nilerr // a discovery error after cancellation is the cancellation itself
			}

			if appMetrics != nil {
				appMetrics.SSFPollError()
			}

			logger.LogAttrs(ctx, slog.LevelError, "unable to set up the SSF receiver after a reload; retrying",
				slog.Any("err", err),
				slog.Duration("retry_in", wait),
			)

			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}

			wait = min(wait*2, ssf.MaxBackoff)
		}
	}, nil
}

// setupSSFReceiver discovers the SSF transmitter and its stream and returns
// a receiver that hands session-revoked events to handler. Discovery errors
// stop the startup, so a misconfigured receiver is noticed at once.
func setupSSFReceiver(
	ctx context.Context, logger *slog.Logger, conf *config.Config, httpClient *http.Client,
	tokens ssf.TokenSource, handler ssf.Handler, appMetrics *metrics.Metrics,
) (*ssf.Receiver, error) {
	issuer := conf.SSFIssuer()

	discovery, err := ssf.Discover(ctx, httpClient, issuer.URL, tokens)
	if err != nil {
		return nil, fmt.Errorf("discover SSF transmitter %s: %w", issuer.String(), err)
	}

	stream := discovery.Stream

	logger.LogAttrs(ctx, slog.LevelInfo, "discovered SSF stream",
		slog.String("issuer", discovery.Metadata.Issuer),
		slog.String("stream_id", stream.StreamID),
		slog.Any("aud", stream.Audience),
		slog.String("endpoint", stream.Delivery.EndpointURL),
	)

	if len(stream.EventsDelivered) > 0 && !slices.Contains(stream.EventsDelivered, ssf.EventTypeSessionRevoked) {
		logger.LogAttrs(ctx, slog.LevelWarn, "the SSF stream does not deliver session-revoked events; no sessions will be revoked",
			slog.Any("events_delivered", stream.EventsDelivered),
		)
	}

	verifier := ssf.NewVerifier(ssf.VerifierConfig{
		KeySet:                 rp.NewRemoteKeySet(httpClient, discovery.Metadata.JWKSURI),
		Issuer:                 discovery.Metadata.Issuer,
		Audience:               stream.Audience,
		CriticalSubjectMembers: discovery.Metadata.CriticalSubjectMembers,
		MaxAge:                 conf.SSF.MaxAge,
		AllowEmail:             conf.SSF.Subject.AllowEmail,
	})

	return ssf.NewReceiver(logger, ssf.ReceiverConfig{
		Client:      httpClient,
		Verifier:    verifier,
		Handler:     handler,
		Metrics:     appMetrics,
		Endpoint:    stream.Delivery.EndpointURL,
		TokenSource: tokens,
		Interval:    conf.SSF.Poll.Interval,
		MaxEvents:   conf.SSF.Poll.MaxEvents,
	}), nil
}

// ssfTokenSource returns the static ssf.poll.token, or access tokens from the
// client credentials grant of the OAuth2 client with ssf.poll.scopes, reused
// until shortly before they expire or until the transmitter rejects them.
func ssfTokenSource(conf *config.Config, client clientCredentials) ssf.TokenSource {
	if token := conf.SSF.Poll.Token.String(); token != "" {
		return ssf.StaticToken(token)
	}

	scopes := conf.SSF.Poll.Scopes

	return ssf.CachedTokenSource(func(ctx context.Context) (*xoauth2.Token, error) {
		return client.ClientCredentialsToken(ctx, scopes...)
	})
}

// clientCredentials requests access tokens with the client credentials
// grant. *oauth2.Client implements it.
type clientCredentials interface {
	ClientCredentialsToken(ctx context.Context, scopes ...string) (*xoauth2.Token, error)
}
