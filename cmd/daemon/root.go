package daemon

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/version"
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

// Execute is the main entry point for the openvpn-auth-oauth2 daemon.
func Execute(args []string, stdout io.Writer, termCh <-chan os.Signal) int {
	tokenDataStorage := tokenstorage.DataMap{}
	ctx := context.Background()

	for {
		if returnCode := run(ctx, args, stdout, tokenDataStorage, termCh); returnCode != ReturnCodeReload {
			return returnCode
		}

		time.Sleep(300 * time.Millisecond) // Wait before reloading configuration
	}
}

// run runs the main program logic of openvpn-auth-oauth2.
func run(ctx context.Context, args []string, stdout io.Writer, tokenDataStorage tokenstorage.DataMap, termCh <-chan os.Signal) ReturnCode {
	conf, logger, rc := initializeConfigAndLogger(args, stdout)
	if rc != ReturnCodeNoError {
		return rc
	}

	// initialize the root context with a cancel function
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	logger.LogAttrs(ctx, slog.LevelDebug, "config", slog.String("config", conf.String()))

	openvpnClient, httpHandler, err := setupOpenVPNClient(ctx, logger, conf, tokenDataStorage)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, err.Error())

		return ReturnCodeError
	}

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	server := startServices(ctx, cancel, wg, logger, conf, openvpnClient, httpHandler)

	logger.LogAttrs(ctx, slog.LevelInfo,
		"openvpn-auth-oauth2 started with base url "+conf.HTTP.BaseURL.String(),
	)

	return handleSignalsAndShutdown(ctx, cancel, termCh, logger, server)
}

func printVersion(writer io.Writer) {
	//goland:noinspection GoBoolExpressions
	if version.Version == "dev" {
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			_, _ = fmt.Fprintf(writer, "version: %s\ngo: %s\n", buildInfo.Main.Version, buildInfo.GoVersion)

			return
		}
	}

	_, _ = fmt.Fprintf(writer, "version: %s\ncommit: %s\ndate: %s\ngo: %s\n", version.Version, version.Commit, version.Date, runtime.Version())
}

// setupConfiguration parses the command line arguments and loads the configuration.
func setupConfiguration(args []string, logWriter io.Writer) (config.Config, error) {
	conf, err := config.New(args, logWriter)
	if err != nil {
		return config.Config{}, fmt.Errorf("configuration error: %w", err)
	}

	if err = config.Validate(config.ManagementClient, conf); err != nil {
		return config.Config{}, fmt.Errorf("configuration validation error: %w", err)
	}

	return conf, nil
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

	var (
		provider oauth2.Provider
	)

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

	oAuth2Client, err := oauth2.New(ctx, logger, conf, httpClient, tokenStorage, provider, openvpnClient)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating oauth2 client: %w", err)
	}

	openvpnClient.SetOAuth2Client(oAuth2Client)

	httpHandler := httphandler.New(conf, oAuth2Client)

	return openvpnClient, httpHandler, nil
}

// initializeConfigAndLogger handles configuration parsing and logger setup.
func initializeConfigAndLogger(args []string, stdout io.Writer) (config.Config, *slog.Logger, ReturnCode) {
	conf, err := setupConfiguration(args, stdout)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return config.Config{}, nil, ReturnCodeOK
		}

		if errors.Is(err, config.ErrVersion) {
			printVersion(stdout)

			return config.Config{}, nil, ReturnCodeOK
		}

		_, _ = fmt.Fprintln(stdout, err.Error())

		return config.Config{}, nil, ReturnCodeError
	}

	logger, err := setupLogger(conf, stdout)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, fmt.Errorf("error setupConfiguration logging: %w", err).Error())

		return config.Config{}, nil, ReturnCodeError
	}

	return conf, logger, ReturnCodeNoError
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
		startDebugListener(ctx, cancel, wg, logger, conf)
	}

	// Start HTTP server
	server := httpserver.NewHTTPServer(httpserver.ServerNameDefault, logger, conf.HTTP, httpHandler)
	startHTTPServer(ctx, cancel, wg, server)

	// Start OpenVPN client
	startOpenVPNClient(ctx, cancel, wg, openvpnClient)

	return server
}

// startDebugListener starts the debug/pprof HTTP server in a goroutine.
func startDebugListener(ctx context.Context, cancel context.CancelCauseFunc, wg *sync.WaitGroup, logger *slog.Logger, conf config.Config) {
	wg.Add(1)

	go func() {
		defer wg.Done()

		cancel(setupDebugListener(ctx, logger, conf))
	}()
}

// startHTTPServer starts the main HTTP server in a goroutine.
func startHTTPServer(ctx context.Context, cancel context.CancelCauseFunc, wg *sync.WaitGroup, server *httpserver.Server) {
	wg.Add(1)

	go func() {
		defer wg.Done()

		if err := server.Listen(ctx); err != nil {
			cancel(fmt.Errorf("error http listener: %w", err))

			return
		}

		cancel(nil)
	}()
}

// startOpenVPNClient starts the OpenVPN client in a goroutine.
func startOpenVPNClient(ctx context.Context, cancel context.CancelCauseFunc, wg *sync.WaitGroup, openvpnClient *openvpn.Client) {
	wg.Add(1)

	go func() {
		defer wg.Done()

		if err := openvpnClient.Connect(ctx); err != nil {
			cancel(fmt.Errorf("openvpn: %w", err))

			return
		}

		cancel(nil)
	}()
}

// handleSignalsAndShutdown manages the main event loop for signals and shutdown.
func handleSignalsAndShutdown(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	termCh <-chan os.Signal,
	logger *slog.Logger,
	server *httpserver.Server,
) ReturnCode {
	for {
		select {
		case <-ctx.Done():
			return handleContextDone(ctx, logger)
		case sig := <-termCh:
			handleSignal(ctx, cancel, sig, logger, server)
		}
	}
}

// handleContextDone processes context cancellation and returns appropriate return code.
func handleContextDone(ctx context.Context, logger *slog.Logger) ReturnCode {
	err := context.Cause(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return ReturnCodeOK
		}

		if errors.Is(err, ErrReload) {
			return ReturnCodeReload
		}

		logger.ErrorContext(ctx, err.Error())

		return ReturnCodeError
	}

	return ReturnCodeOK
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
		if err := server.Reload(); err != nil {
			cancel(fmt.Errorf("error reloading http server: %w", err))
		}
	case syscall.SIGUSR1:
		logger.LogAttrs(ctx, slog.LevelInfo, "reloading configuration")
		cancel(ErrReload)
	default:
		cancel(nil)
	}
}
