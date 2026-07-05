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

// runLoop is the main entry point for the openvpn-auth-oauth2 daemon.
func runLoop(args []string, stdout io.Writer, termCh <-chan os.Signal) int {
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

	logger.LogAttrs(
		ctx, slog.LevelDebug, "config",
		slog.String("config", conf.String()),
	)

	tokenStorage := tokenstorage.NewInMemory(conf.OAuth2.Refresh.Secret.String(), conf.OAuth2.Refresh.Expires)
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

		return ReturnCodeError
	}

	appRuntime, err := daemon.New(ctx, logger, conf, tokenStorage)
	if err != nil {
		logger.LogAttrs(
			ctx, slog.LevelError, err.Error(),
			slog.Any("err", err),
		)

		return ReturnCodeError
	}

	appRuntime.Start(ctx)
	defer appRuntime.Wait()

	logger.LogAttrs(
		ctx, slog.LevelInfo,
		"openvpn-auth-oauth2 started with base url "+conf.HTTP.BaseURL.String(),
	)

	return handleSignalsAndShutdown(ctx, termCh, logger, appRuntime)
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
	conf, err := setupConfiguration(args, stdout)
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

	logger, err := setupLogger(conf, stdout)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, fmt.Errorf("error setupConfiguration logging: %w", err).Error())

		return nil, nil, ReturnCodeError
	}

	return conf, logger, ReturnCodeNoError
}

// handleSignalsAndShutdown manages the main event loop for signals and shutdown.
func handleSignalsAndShutdown(
	ctx context.Context,
	termCh <-chan os.Signal,
	logger *slog.Logger,
	appRuntime *daemon.Runtime,
) ReturnCode {
	for {
		select {
		case <-appRuntime.Done():
			return handleContextDone(ctx, logger, appRuntime.Err())
		case sig := <-termCh:
			handleSignal(ctx, sig, logger, appRuntime)
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
func handleSignal(
	ctx context.Context,
	sig os.Signal,
	logger *slog.Logger,
	appRuntime *daemon.Runtime,
) {
	logger.LogAttrs(ctx, slog.LevelInfo, "receiving signal: "+sig.String())

	switch sig {
	case syscall.SIGHUP:
		if err := appRuntime.Reload(ctx); err != nil {
			appRuntime.Stop(err)
		}
	case SIGUSR1:
		logger.LogAttrs(ctx, slog.LevelInfo, "reloading configuration")
		appRuntime.Stop(ErrReload)
	default:
		appRuntime.Stop(nil)
	}
}
