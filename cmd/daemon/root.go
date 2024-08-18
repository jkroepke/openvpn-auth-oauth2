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
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

// Execute runs the main program logic of openvpn-auth-oauth2.
//
//nolint:cyclop
func Execute(args []string, logWriter io.Writer, version, commit, date string) int {
	var err error

	logger := defaultLogger(logWriter)

	flagSet := config.FlagSet(args[0])
	flagSet.SetOutput(logWriter)

	if err = flagSet.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		logger.Error(fmt.Errorf("error parsing cli args: %w", err).Error())

		return 1
	}

	if flagSet.Lookup("version").Value.String() == "true" {
		_, _ = fmt.Fprintf(logWriter, "version: %s\ncommit: %s\ndate: %s\ngo: %s\n", version, commit, date, runtime.Version())

		return 0
	}

	conf, err := config.Load(config.ManagementClient, flagSet.Lookup("config").Value.String(), flagSet)
	if err != nil {
		logger.Error(fmt.Errorf("error loading config: %w", err).Error())

		return 1
	}

	logger, err = configureLogger(conf, logWriter)
	if err != nil {
		logger = defaultLogger(logWriter)
		logger.Error(fmt.Errorf("error configure logging: %w", err).Error())

		return 1
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	httpClient := &http.Client{Transport: utils.NewUserAgentTransport(http.DefaultTransport)}
	storageClient := storage.New(ctx, conf.OAuth2.Refresh.Secret.String(), conf.OAuth2.Refresh.Expires)
	oauth2Client := oauth2.New(logger, conf, storageClient, httpClient)
	openvpnClient := openvpn.New(ctx, logger, conf, oauth2Client)

	if err = oauth2Client.Initialize(ctx, openvpnClient); err != nil {
		logger.Error(err.Error())

		return 1
	}

	wg := sync.WaitGroup{}
	defer wg.Wait()

	if conf.Debug.Pprof {
		wg.Add(1)

		go func() {
			defer wg.Done()

			cancel(setupDebugListener(ctx, logger, conf))
		}()
	}

	server := httpserver.NewHTTPServer(httpserver.ServerNameDefault, logger, conf.HTTP, oauth2Client.Handler())

	wg.Add(1)

	go func() {
		defer wg.Done()

		if err := server.Listen(ctx); err != nil {
			cancel(fmt.Errorf("error http listener: %w", err))

			return
		}

		cancel(nil)
	}()

	wg.Add(1)

	go func() {
		defer wg.Done()

		if err := openvpnClient.Connect(); err != nil {
			cancel(fmt.Errorf("OpenVPN: %w", err))

			return
		}

		cancel(nil)
	}()

	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)

	logger.Info(
		"openvpn-auth-oauth2 started with base url " + conf.HTTP.BaseURL.String(),
	)

	for {
		select {
		case <-ctx.Done():
			err = context.Cause(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Error(err.Error())

				return 1
			}

			return 0
		case sig := <-termCh:
			logger.Info("receiving signal: " + sig.String())

			switch sig {
			case syscall.SIGHUP:
				if err = server.Reload(); err != nil {
					err := fmt.Errorf("error reloading http server: %w", err)
					logger.Error(err.Error())

					cancel(err)
				}
			default:
				cancel(nil)
			}
		}
	}
}

func setupDebugListener(ctx context.Context, logger *slog.Logger, conf config.Config) error {
	mux := http.NewServeMux()
	mux.Handle("/", http.RedirectHandler("/debug/pprof/", http.StatusTemporaryRedirect))
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := httpserver.NewHTTPServer(httpserver.ServerNameDebug, logger, config.HTTP{Listen: conf.Debug.Listen}, mux)

	err := server.Listen(ctx)
	if err != nil {
		return fmt.Errorf("error debug http listener: %w", err)
	}

	return nil
}

func defaultLogger(writer io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{
		AddSource: false,
	}))
}

func configureLogger(conf config.Config, writer io.Writer) (*slog.Logger, error) {
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
