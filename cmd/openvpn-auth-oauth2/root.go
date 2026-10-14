// Explicitly disable httpmuxgo121, because Debian build system disables it.
// ref: https://github.com/jkroepke/openvpn-auth-oauth2/issues/680#issuecomment-3686988447
//go:debug httpmuxgo121=0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/daemon"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/version"
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

func main() {
	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, SIGUSR1)

	os.Exit(runLoop(os.Args, os.Stdout, termCh)) //nolint:forbidigo // entry point
}

// loadedConfig is a parsed and validated configuration with its logger.
type loadedConfig struct {
	conf   *config.Config
	logger *slog.Logger
}

// configLoader parses and validates the configuration again for a reload.
type configLoader func() (loadedConfig, error)

// runLoop is the main entry point for the openvpn-auth-oauth2 daemon.
func runLoop(args []string, stdout io.Writer, termCh <-chan os.Signal) int {
	// Refresh tokens and the session registry describe OpenVPN clients,
	// not the configuration, so they outlive configuration reloads.
	tokenDataStorage := tokenstorage.DataMap{}
	sessions := sessionregistry.New()
	ctx := context.Background()

	conf, logger, rc := initializeConfigAndLogger(args, stdout)
	if rc != ReturnCodeNoError {
		return rc
	}

	current := loadedConfig{conf: conf, logger: logger}
	loadConfig := func() (loadedConfig, error) {
		conf, logger, err := loadConfigAndLogger(args, stdout)

		return loadedConfig{conf: conf, logger: logger}, err
	}

	for {
		returnCode, next := run(ctx, current, tokenDataStorage, sessions, termCh, loadConfig)
		if returnCode != ReturnCodeReload {
			return returnCode
		}

		current = next
		// Use the reloaded logger for dependencies that log through package-level slog functions.
		slog.SetDefault(current.logger)

		time.Sleep(300 * time.Millisecond) // Wait before reloading configuration
	}
}

// run runs the main program logic of openvpn-auth-oauth2 for one loaded configuration.
// On a configuration reload, it returns ReturnCodeReload and the already validated next configuration.
func run(
	ctx context.Context, current loadedConfig, tokenDataStorage tokenstorage.DataMap, sessions *sessionregistry.Registry,
	termCh <-chan os.Signal, loadConfig configLoader,
) (ReturnCode, loadedConfig) {
	conf, logger := current.conf, current.logger

	logger.LogAttrs(
		ctx, slog.LevelDebug, "config",
		slog.String("config", conf.String()),
	)

	tokenStorage, err := tokenstorage.NewInMemory(conf.OAuth2.Refresh.Secret.String(), conf.OAuth2.Refresh.Expires)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelError, "error creating token storage", slog.Any("err", err))

		return ReturnCodeError, loadedConfig{}
	}

	defer func() {
		if err := tokenStorage.Close(); err != nil {
			logger.LogAttrs(ctx, slog.LevelError, "error closing token storage", slog.Any("err", err))
		}
	}()

	if err := tokenStorage.SetStorage(tokenDataStorage); err != nil {
		logger.LogAttrs(
			ctx, slog.LevelError, "error setting token storage",
			slog.Any("err", err),
		)

		return ReturnCodeError, loadedConfig{}
	}

	appRuntime, err := daemon.New(ctx, logger, conf, tokenStorage, sessions)
	if err != nil {
		logger.LogAttrs(
			ctx, slog.LevelError, err.Error(),
			slog.Any("err", err),
		)

		return ReturnCodeError, loadedConfig{}
	}

	appRuntime.Start(ctx)
	defer appRuntime.Wait()

	logger.LogAttrs(
		ctx, slog.LevelInfo,
		"openvpn-auth-oauth2 started with base url "+conf.HTTP.BaseURL.String(),
	)

	return handleSignalsAndShutdown(ctx, termCh, logger, appRuntime, loadConfig)
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
func setupConfiguration(args []string, logWriter io.Writer) (*config.Config, error) {
	conf, err := config.New(args, logWriter)
	if err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	if err = config.Validate(config.ManagementClient, conf); err != nil {
		return nil, fmt.Errorf("configuration validation error: %w", err)
	}

	return conf, nil
}

// setupLogger initializes the logger based on the configuration.
func setupLogger(conf *config.Config, writer io.Writer) (*slog.Logger, error) {
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

// initializeConfigAndLogger handles configuration parsing and logger setup.
func initializeConfigAndLogger(args []string, stdout io.Writer) (*config.Config, *slog.Logger, ReturnCode) {
	conf, logger, err := loadConfigAndLogger(args, stdout)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil, ReturnCodeOK
		}

		if errors.Is(err, config.ErrVersion) {
			printVersion(stdout)

			return nil, nil, ReturnCodeOK
		}

		_, _ = fmt.Fprintln(stdout, err.Error())

		return nil, nil, ReturnCodeError
	}

	// Use the configured logger for dependencies that log through package-level slog functions.
	slog.SetDefault(logger)

	return conf, logger, ReturnCodeNoError
}

// loadConfigAndLogger parses and validates the configuration and creates its logger
// without changing any process-wide state.
func loadConfigAndLogger(args []string, stdout io.Writer) (*config.Config, *slog.Logger, error) {
	conf, err := setupConfiguration(args, stdout)
	if err != nil {
		return nil, nil, err
	}

	logger, err := setupLogger(conf, stdout)
	if err != nil {
		return nil, nil, fmt.Errorf("error setupConfiguration logging: %w", err)
	}

	return conf, logger, nil
}

// handleSignalsAndShutdown manages the main event loop for signals and shutdown.
func handleSignalsAndShutdown(
	ctx context.Context,
	termCh <-chan os.Signal,
	logger *slog.Logger,
	appRuntime *daemon.Runtime,
	loadConfig configLoader,
) (ReturnCode, loadedConfig) {
	var next loadedConfig

	for {
		select {
		case <-appRuntime.Done():
			return handleContextDone(ctx, logger, appRuntime.Err()), next
		case sig := <-termCh:
			if reloaded, ok := handleSignal(ctx, sig, logger, appRuntime, loadConfig); ok {
				next = reloaded
			}
		}
	}
}

// handleContextDone processes context cancellation and returns appropriate return code.
func handleContextDone(ctx context.Context, logger *slog.Logger, err error) ReturnCode {
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
// For SIGUSR1, it returns the validated next configuration and true if the runtime was stopped for a reload.
func handleSignal(
	ctx context.Context,
	sig os.Signal,
	logger *slog.Logger,
	appRuntime *daemon.Runtime,
	loadConfig configLoader,
) (loadedConfig, bool) {
	logger.LogAttrs(ctx, slog.LevelInfo, "receiving signal: "+sig.String())

	switch sig {
	case syscall.SIGHUP:
		if err := appRuntime.Reload(ctx); err != nil {
			appRuntime.Stop(err)
		}
	case SIGUSR1:
		logger.LogAttrs(ctx, slog.LevelInfo, "reloading configuration")

		next, err := loadConfig()
		if err != nil {
			logger.LogAttrs(
				ctx, slog.LevelError, "configuration reload failed, keeping current configuration",
				slog.Any("err", err),
			)

			return loadedConfig{}, false
		}

		appRuntime.Stop(ErrReload)

		return next, true
	default:
		appRuntime.Stop(nil)
	}

	return loadedConfig{}, false
}
