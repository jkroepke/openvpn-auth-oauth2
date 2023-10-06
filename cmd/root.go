package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/http"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

func Execute(args []string, logWriter io.Writer, version, commit, date string) int {
	var err error

	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{
		AddSource: false,
	}))

	flagSet := config.FlagSet()
	if err = flagSet.Parse(args[1:]); err != nil {
		logger.Error(fmt.Errorf("error parsing cli args: %w", err).Error())

		return 1
	}

	if versionFlag, _ := flagSet.GetBool("version"); versionFlag {
		fmt.Printf("version: %s\ncommit: %s\ndate: %s\ngo: %s\n", version, commit, date, runtime.Version())

		return 0
	}

	configFile, _ := flagSet.GetString("config")

	conf, err := config.Load(config.ManagementClient, configFile, flagSet)
	if err != nil {
		logger.Error(fmt.Errorf("error loading config: %w", err).Error())

		return 1
	}

	logger, err = configureLogger(conf, logWriter)
	if err != nil {
		logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{
			AddSource: false,
		}))
		logger.Error(fmt.Errorf("error configure logging: %w", err).Error())

		return 1
	}

	provider, err := oauth2.NewProvider(logger, conf)
	if err != nil {
		logger.Error(err.Error())

		return 1
	}

	openvpnClient := openvpn.NewClient(logger, conf)
	done := make(chan int, 1)

	serverHandler := oauth2.Handler(logger, conf, provider, openvpnClient)
	server := http.NewHTTPServer(logger, conf, serverHandler)

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
	signal.Notify(termCh, syscall.SIGINT, syscall.SIGTERM)

	var returnCode int
	select {
	case returnCode = <-done:
	case sig := <-termCh:
		logger.Info(utils.StringConcat("receiving signal: ", sig.String()))
	}

	shutdown(logger, openvpnClient, server)

	return returnCode
}

func shutdown(logger *slog.Logger, openvpnClient *openvpn.Client, server http.Server) {
	openvpnClient.Shutdown()

	logger.Info("start graceful shutdown of http listener")

	if err := server.Shutdown(); err != nil {
		logger.Error(fmt.Errorf("error graceful shutdown: %w", err).Error())

		return
	}

	logger.Info("http listener successfully terminated")
}

func configureLogger(conf config.Config, writer io.Writer) (*slog.Logger, error) {
	var level slog.Level

	err := level.UnmarshalText([]byte(conf.Log.Level))
	if err != nil {
		return nil, fmt.Errorf("unable to parse log level: %w", err)
	}

	opts := &slog.HandlerOptions{
		AddSource: false,
		Level:     level,
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
