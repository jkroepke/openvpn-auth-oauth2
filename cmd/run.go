package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/crypto"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ReturnCode = int

const (
	// ReturnCodeNoError indicates that the program should continue running.
	ReturnCodeNoError ReturnCode = -2
	// ReturnCodeReload indicates that the configuration should be reloaded.
	ReturnCodeReload ReturnCode = -1
	// ReturnCodeOK indicates a successful execution of the program.
	ReturnCodeOK ReturnCode = 0
	// ReturnCodeError indicates an error during execution.
	ReturnCodeError ReturnCode = 1
)

var ErrReload = errors.New("reload")

// execute is the main entry point for the openvpn-auth-oauth2 daemon.
func runLoop(cmd *cobra.Command, _ []string) error {
	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, SIGUSR1)

	tokenDataStorage := tokenstorage.DataMap{}

	var err error

	for {
		err = run(cmd.Context(), tokenDataStorage, termCh)
		if !errors.Is(err, ErrReload) {
			return err
		}

		time.Sleep(300 * time.Millisecond) // Wait before reloading configuration
	}
}

// run runs the main program logic of openvpn-auth-oauth2.
func run(ctx context.Context, tokenDataStorage tokenstorage.DataMap, termCh <-chan os.Signal) error {
	conf, logger, err := initializeConfigAndLogger()
	if err != nil {
		return err
	}

	// initialize the root context with a cancel function
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	logger.LogAttrs(ctx, slog.LevelDebug, "config",
		slog.String("config", conf.String()),
	)

	openvpnClient, httpHandler, err := setupOpenVPNClient(ctx, logger, conf, tokenDataStorage)
	if err != nil {
		return fmt.Errorf("error setting up openvpn client: %w", err)
	}

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	server := startServices(ctx, cancel, wg, logger, conf, openvpnClient, httpHandler)

	logger.LogAttrs(ctx, slog.LevelInfo,
		"openvpn-auth-oauth2 started with base url "+conf.HTTP.BaseURL.String(),
	)

	return handleSignalsAndShutdown(ctx, cancel, termCh, logger, server)
}

// setupLogger initializes the logger based on the configuration.
func setupLogger(conf config.Config, writer io.Writer) (*slog.Logger, error) {
	opts := &slog.HandlerOptions{
		AddSource: false,
		Level:     conf.Log.Level,
	}

	switch conf.Log.Format {
	case "json":
		return slog.New(slog.NewJSONHandler(writer, opts)), nil
	case "console":
		return slog.New(slog.NewTextHandler(writer, opts)), nil
	default:
		return nil, fmt.Errorf("unknown log format: %s", conf.Log.Format)
	}
}

// setupDebugListener sets up an HTTP server for debugging purposes, including pprof endpoints.
func setupDebugListener(ctx context.Context, logger *slog.Logger, conf config.Config) error {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.RedirectHandler("/debug/pprof/", http.StatusTemporaryRedirect))
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)

	server := httpserver.NewHTTPServer(httpserver.ServerNameDebug, logger, config.HTTP{Listen: conf.Debug.Listen}, mux)

	err := server.Listen(ctx)
	if err != nil {
		return fmt.Errorf("error debug http listener: %w", err)
	}

	return nil
}

// setupOpenVPNClient initializes the OpenVPN client with the provided configuration and OAuth2 provider.
func setupOpenVPNClient(
	ctx context.Context, logger *slog.Logger, conf config.Config, tokenDataStorage tokenstorage.DataMap,
) (*openvpn.Client, *http.ServeMux, error) {
	httpClient := &http.Client{Transport: utils.NewUserAgentTransport(http.DefaultTransport)}
	tokenStorage := tokenstorage.NewInMemory(conf.OAuth2.Refresh.Secret.String(), conf.OAuth2.Refresh.Expires)

	err := tokenStorage.SetStorage(tokenDataStorage)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting token storage: %w", err)
	}

	var provider oauth2.Provider

	switch conf.OAuth2.Provider {
	case generic.Name:
		provider, err = generic.NewProvider(ctx, conf, httpClient)
	case github.Name:
		provider, err = github.NewProvider(ctx, conf, httpClient)
	case google.Name:
		provider, err = google.NewProvider(ctx, conf, httpClient)
	default:
		err = errors.New("unknown oauth2 provider: " + conf.OAuth2.Provider)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("error creating oauth2 provider: %w", err)
	}

	openvpnClient := openvpn.New(logger, conf)

	oAuth2Client, err := oauth2.New(ctx, logger, conf, httpClient, tokenStorage, crypto.New(conf.HTTP.Secret.String()), provider, openvpnClient)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating oauth2 client: %w", err)
	}

	openvpnClient.SetOAuth2Client(oAuth2Client)

	httpHandler := httphandler.New(conf, oAuth2Client)

	return openvpnClient, httpHandler, nil
}

// initializeConfigAndLogger handles configuration parsing and logger setup.
func initializeConfigAndLogger() (config.Config, *slog.Logger, error) {
	conf := config.Defaults

	err := viper.Unmarshal(&conf, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToURLHookFunc(),
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.TextUnmarshallerHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			mapstructure.StringToBasicTypeHookFunc(),
		)),
	)

	if err != nil {
		return config.Config{}, nil, fmt.Errorf("configuration loading error: %w", err)
	}

	err = config.Validate(conf)
	if err != nil {
		return config.Config{}, nil, fmt.Errorf("configuration validation error: %w", err)
	}

	logger, err := setupLogger(conf, os.Stdout)
	if err != nil {
		return config.Config{}, nil, fmt.Errorf("setup logging error: %w", err)
	}

	logWarnings(logger, conf)

	return conf, logger, nil
}

func logWarnings(logger *slog.Logger, conf config.Config) {
	if conf.OAuth2.Validate.CEL != "" {
		logger.Warn("Using CEL validation is experimental and may not be suitable for production use.")
	}
	/*
		if conf.OAuth2.Validate.CommonName != "" {
			logger.Info("using Common Name validation is deprecated and removed in 2.0. Consider using CEL validation instead.")
		}

		if conf.OAuth2.Validate.IPAddr {
			logger.Info("using IP Address validation is deprecated and removed in 2.0. Consider using CEL validation instead.")
		}

		if len(conf.OAuth2.Validate.Acr) > 0 {
			logger.Info("using ACR validation is deprecated and removed in 2.0. Consider using CEL validation instead.")
		}

		if len(conf.OAuth2.Validate.Groups) > 0 {
			logger.Info("using Groups validation is deprecated and removed in 2.0. Consider using CEL validation instead.")
		}

		if len(conf.OAuth2.Validate.Roles) > 0 {
			logger.Info("using Roles validation is deprecated and removed in 2.0. Consider using CEL validation instead.")
		}
	*/
}

// startServices starts all the background services (HTTP server, OpenVPN client, debug listener).
func startServices(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	wg *sync.WaitGroup,
	logger *slog.Logger,
	conf config.Config,
	openvpnClient *openvpn.Client,
	httpHandler *http.ServeMux,
) *httpserver.Server {
	// Start debug listener if enabled
	if conf.Debug.Pprof {
		wg.Go(func() {
			cancel(setupDebugListener(ctx, logger, conf))
		})
	}

	// Start HTTP server
	server := httpserver.NewHTTPServer(httpserver.ServerNameDefault, logger, conf.HTTP, httpHandler)
	startHTTPServer(ctx, cancel, wg, server)

	// Start OpenVPN client
	startOpenVPNClient(ctx, cancel, wg, openvpnClient)

	return server
}

// startHTTPServer starts the main HTTP server in a goroutine.
func startHTTPServer(ctx context.Context, cancel context.CancelCauseFunc, wg *sync.WaitGroup, server *httpserver.Server) {
	wg.Go(func() {
		if err := server.Listen(ctx); err != nil {
			cancel(fmt.Errorf("error http listener: %w", err))

			return
		}

		cancel(nil)
	})
}

// startOpenVPNClient starts the OpenVPN client in a goroutine.
func startOpenVPNClient(ctx context.Context, cancel context.CancelCauseFunc, wg *sync.WaitGroup, openvpnClient *openvpn.Client) {
	wg.Go(func() {
		if err := openvpnClient.Connect(ctx); err != nil {
			cancel(fmt.Errorf("openvpn: %w", err))

			return
		}

		cancel(nil)
	})
}

// handleSignalsAndShutdown manages the main event loop for signals and shutdown.
func handleSignalsAndShutdown(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	termCh <-chan os.Signal,
	logger *slog.Logger,
	server *httpserver.Server,
) error {
	for {
		select {
		case <-ctx.Done():
			return handleContextDone(ctx)
		case sig := <-termCh:
			handleSignal(ctx, cancel, sig, logger, server)
		}
	}
}

// handleContextDone processes context cancellation and returns appropriate return code.
func handleContextDone(ctx context.Context) error {
	err := context.Cause(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}

		return err
	}

	return nil
}

// handleSignal processes incoming OS signals.
func handleSignal(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	sig os.Signal,
	logger *slog.Logger,
	server *httpserver.Server,
) {
	logger.LogAttrs(ctx, slog.LevelInfo, "receiving signal: "+sig.String())

	switch sig {
	case syscall.SIGHUP:
		if err := server.Reload(ctx); err != nil {
			cancel(fmt.Errorf("error reloading http server: %w", err))
		}
	case SIGUSR1:
		logger.LogAttrs(ctx, slog.LevelInfo, "reloading configuration")
		cancel(ErrReload)
	default:
		cancel(nil)
	}
}
