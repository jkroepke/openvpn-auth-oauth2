package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/mitchellh/mapstructure"
	flag "github.com/spf13/pflag"
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

	conf, err := loadConfig(flagSet)
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

	server := &http.Server{
		Addr:              conf.HTTP.Listen,
		ReadHeaderTimeout: 3 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
		Handler:           oauth2.Handler(logger, conf, provider, openvpnClient),
	}

	go func() {
		if err := startHTTPListener(conf, logger, server); err != nil {

			logger.Error(fmt.Errorf("error http listener: %w", err).Error())
			done <- 1
		}
	}()

	go func() {
		if err := openvpnClient.Connect(); err != nil {
			logger.Error(fmt.Errorf("error OpenVPN: %w", err).Error())
			done <- 1
		}
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

func shutdown(logger *slog.Logger, openvpnClient *openvpn.Client, server *http.Server) {
	openvpnClient.Shutdown()

	logger.Info("start graceful shutdown of http listener")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error(fmt.Errorf("error graceful shutdown: %w", err).Error())

		return
	}

	logger.Info("http listener successfully terminated")
}

func startHTTPListener(conf config.Config, logger *slog.Logger, server *http.Server) error {
	if conf.HTTP.TLS {
		logger.Info(utils.StringConcat(
			"HTTPS server listen on ", conf.HTTP.Listen, " with base url ", conf.HTTP.BaseURL.String(),
		))

		err := server.ListenAndServeTLS(conf.HTTP.CertFile, conf.HTTP.KeyFile)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("ListenAndServeTLS: %w", err)
		}

		return nil
	}

	logger.Info(utils.StringConcat(
		"HTTP server listen on ", conf.HTTP.Listen, " with base url ", conf.HTTP.BaseURL.String(),
	))

	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("ListenAndServe: %w", err)
	}

	return nil
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

func loadConfig(flagSet *flag.FlagSet) (config.Config, error) {
	var err error

	k := koanf.New(".")

	configFile, _ := flagSet.GetString("config")
	if configFile != "" {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			return config.Config{}, fmt.Errorf("error from file provider: %w", err)
		}
	}

	if err = k.Load(posflag.Provider(flagSet, ".", k), nil); err != nil {
		return config.Config{}, fmt.Errorf("error from posflag provider: %w", err)
	}

	err = k.Load(env.ProviderWithValue("CONFIG_", ".",
		func(envKey string, envValue string) (string, interface{}) {
			key := strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(envKey, "CONFIG_")), "_", ".")

			// If there is a space in the value, split the value into a slice by the space.
			if strings.Contains(envValue, " ") {
				return key, strings.Split(envValue, " ")
			}

			// Otherwise, return the plain string.
			return key, envValue
		}), nil,
	)

	if err != nil {
		return config.Config{}, fmt.Errorf("error from env provider: %w", err)
	}

	var conf config.Config
	unmarshalConf := koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.TextUnmarshallerHookFunc(),
				config.StringToURLHookFunc(),
				config.StringToTemplateHookFunc(),
			),
			Metadata:         nil,
			Result:           &conf,
			WeaklyTypedInput: true,
		},
	}

	if err = k.UnmarshalWithConf("", &conf, unmarshalConf); err != nil {
		return config.Config{}, fmt.Errorf("error unmarschal config: %w", err)
	}

	if err = config.Validate(conf); err != nil {
		return config.Config{}, fmt.Errorf("error validating logging: %w", err)
	}

	return conf, nil
}
