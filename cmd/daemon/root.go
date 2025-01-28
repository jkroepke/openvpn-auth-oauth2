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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

// Execute runs the main program logic of openvpn-auth-oauth2.
//
//nolint:cyclop
func Execute(args []string, logWriter io.Writer, version, commit, date string) int {
	conf, err := configure(args, logWriter, version, commit, date)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		_, _ = fmt.Fprintln(logWriter, err.Error())

		return 1
	}

	logger, err := configureLogger(conf, logWriter)
	if err != nil {
		_, _ = fmt.Fprintln(logWriter, fmt.Errorf("error configure logging: %w", err).Error())

		return 1
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	httpClient := &http.Client{Transport: utils.NewUserAgentTransport(http.DefaultTransport)}
	tokenStorage := tokenstorage.NewInMemory(ctx, conf.OAuth2.Refresh.Secret.String(), conf.OAuth2.Refresh.Expires)

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
		logger.Error(err.Error())

		return 1
	}

	openvpnClient := openvpn.New(logger, conf)

	oAuth2Client, err := oauth2.New(ctx, logger, conf, httpClient, tokenStorage, provider, openvpnClient)
	if err != nil {
		logger.Error(err.Error())

		return 1
	}

	openvpnClient.SetOAuth2Client(oAuth2Client)

	httpHandler, err := httphandler.New(conf, oAuth2Client)
	if err != nil {
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

	server := httpserver.NewHTTPServer(httpserver.ServerNameDefault, logger, conf.HTTP, httpHandler)

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

		if err := openvpnClient.Connect(ctx); err != nil {
			cancel(fmt.Errorf("openvpn: %w", err))

			return
		}

		cancel(nil)
	}()

	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)

	logger.LogAttrs(ctx, slog.LevelInfo,
		"openvpn-auth-oauth2 started with base url "+conf.HTTP.BaseURL.String(),
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
					cancel(fmt.Errorf("error reloading http server: %w", err))
				}
			default:
				cancel(nil)
			}
		}
	}
}

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

// configure parses the command line arguments and loads the configuration.
func configure(args []string, logWriter io.Writer, version, commit, date string) (config.Config, error) {
	flagSet := config.FlagSet(args[0])
	flagSet.SetOutput(logWriter)

	if err := flagSet.Parse(args[1:]); err != nil {
		return config.Config{}, fmt.Errorf("error parsing cli args: %w", err)
	}

	if flagSet.Lookup("version").Value.String() == "true" {
		_, _ = fmt.Fprintf(logWriter, "version: %s\ncommit: %s\ndate: %s\ngo: %s\n", version, commit, date, runtime.Version())

		return config.Config{}, flag.ErrHelp
	}

	conf, err := config.Load(config.ManagementClient, flagSet.Lookup("config").Value.String(), flagSet)
	if err != nil {
		return config.Config{}, fmt.Errorf("error loading config: %w", err)
	}

	return conf, nil
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
