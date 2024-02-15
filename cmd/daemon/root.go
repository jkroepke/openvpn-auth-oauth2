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
	"syscall"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
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
		fmt.Fprintf(logWriter, "version: %s\ncommit: %s\ndate: %s\ngo: %s\n", version, commit, date, runtime.Version())

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

	ctx := context.Background()

	storageClient := storage.New(conf.OAuth2.Refresh.Secret.String(), conf.OAuth2.Refresh.Expires)
	oauth2Client := oauth2.New(logger, conf, storageClient)
	openvpnClient := openvpn.NewClient(ctx, logger, conf, oauth2Client)

	if err = oauth2Client.Initialize(openvpnClient); err != nil {
		logger.Error(err.Error())

		return 1
	}

	done := make(chan int, 1)

	if conf.Debug.Pprof {
		go setupDebugListener(logger, conf, done)
	}

	server := httpserver.NewHTTPServer(logger, conf, oauth2Client.Handler())

	go func() {
		if err := server.Listen(); err != nil {
			logger.Error(fmt.Errorf("error http listener: %w", err).Error())
			done <- 1

			return
		}

		done <- 0
	}()

	go func() {
		if err := openvpnClient.Connect(); err != nil {
			logger.Error(fmt.Errorf("error OpenVPN: %w", err).Error())
			done <- 1

			return
		}

		done <- 0
	}()

	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, os.Interrupt, syscall.SIGTERM)

	var returnCode int
	select {
	case returnCode = <-done:
	case sig := <-termCh:
		logger.Info("receiving signal: " + sig.String())
	}

	shutdown(logger, openvpnClient, server)

	return returnCode
}

func setupDebugListener(logger *slog.Logger, conf config.Config, done chan int) {
	logger.Warn("start HTTP debug server on " + conf.Debug.Listen)

	mux := http.NewServeMux()
	mux.Handle("/", http.RedirectHandler("/debug/pprof/", http.StatusTemporaryRedirect))
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := &http.Server{
		Addr:              conf.Debug.Listen,
		ReadHeaderTimeout: 3 * time.Second,
		Handler:           mux,
	}

	if err := server.ListenAndServe(); err != nil {
		logger.Error(fmt.Errorf("error http debug listener: %w", err).Error())
		done <- 1

		return
	}

	done <- 0
}

func shutdown(logger *slog.Logger, openvpnClient *openvpn.Client, server httpserver.Server) {
	openvpnClient.Shutdown()

	logger.Info("start graceful shutdown of http listener")

	if err := server.Shutdown(); err != nil {
		logger.Error(fmt.Errorf("error graceful shutdown: %w", err).Error())

		return
	}

	logger.Info("http listener successfully terminated")
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
