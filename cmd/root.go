package cmd

import (
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

var k = koanf.New(".")

func Execute(args []string, w io.Writer, version, commit, date string) int {
	var err error

	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		AddSource: false,
	}))

	f := config.FlagSet()
	if err = f.Parse(args[1:]); err != nil {
		logger.Error(utils.StringConcat("error parsing cli args: ", err.Error()))
		return 1
	}

	if versionFlag, _ := f.GetBool("version"); versionFlag {
		fmt.Printf("version: %s\ncommit: %s\ndate: %s\ngo: %s\n", version, commit, date, runtime.Version())
		return 0
	}

	conf, err := loadConfig(f)
	if err != nil {
		logger.Error(utils.StringConcat("error loading config: ", err.Error()))
		return 1
	}

	logger, err = configureLogger(conf, w)
	if err != nil {
		logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
			AddSource: false,
		}))
		logger.Error(utils.StringConcat("error configure logging: ", err.Error()))
		return 1
	}

	if err = config.Validate(conf); err != nil {
		logger.Error(utils.StringConcat("error validating config: ", err.Error()))
		return 1
	}

	oidcClient, err := oauth2.NewProvider(logger, conf)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}

	openvpnClient := openvpn.NewClient(logger, conf)
	done := make(chan int, 1)

	go func() {
		if err = startHttpListener(conf, logger, oidcClient, openvpnClient); err != nil {
			logger.Error(err.Error())
			done <- 1
			return
		}
		done <- 0
	}()

	go func() {
		defer openvpnClient.Shutdown()
		if err = openvpnClient.Connect(); err != nil {
			logger.Error(err.Error())
			done <- 1
			return
		}
		done <- 0
	}()

	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case returnCode := <-done:
		return returnCode
	case sig := <-termCh:
		logger.Info(utils.StringConcat("receiving signal: ", sig.String()))
		openvpnClient.Shutdown()
		return 0
	}
}

func startHttpListener(conf config.Config, logger *slog.Logger, oidcClient *oauth2.Provider, openvpnClient *openvpn.Client) error {
	server := &http.Server{
		Addr:     conf.Http.Listen,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
		Handler:  oauth2.Handler(logger, oidcClient, conf, openvpnClient),
	}

	if conf.Http.Tls {
		logger.Info(utils.StringConcat("HTTPS server listen on ", conf.Http.Listen, " with base url ", conf.Http.BaseUrl.String()))
		return server.ListenAndServeTLS(conf.Http.CertFile, conf.Http.KeyFile)
	}

	logger.Info(utils.StringConcat("HTTP server listen on ", conf.Http.Listen, " with base url ", conf.Http.BaseUrl.String()))
	return server.ListenAndServe()
}

func configureLogger(conf config.Config, w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(conf.Log.Level)); err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{
		AddSource: false,
		Level:     level,
	}

	switch conf.Log.Format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "console":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, errors.New(utils.StringConcat("Unknown log format: ", conf.Log.Format))
	}
}

func loadConfig(f *flag.FlagSet) (config.Config, error) {
	var err error
	configFile, _ := f.GetString("config")
	if configFile != "" {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			return config.Config{}, err
		}
	}

	if err = k.Load(posflag.Provider(f, ".", k), nil); err != nil {
		return config.Config{}, err
	}

	err = k.Load(env.ProviderWithValue("CONFIG_", ".", func(s string, v string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(s, "CONFIG_")), "_", ".", -1)

		// If there is a space in the value, split the value into a slice by the space.
		if strings.Contains(v, " ") {
			return key, strings.Split(v, " ")
		}

		// Otherwise, return the plain string.
		return key, v
	}), nil)

	if err != nil {
		return config.Config{}, err
	}

	var conf config.Config
	unmarshalConf := koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.TextUnmarshallerHookFunc(),
				config.StringToUrlHookFunc(),
				config.StringToTemplateHookFunc(),
			),
			Metadata:         nil,
			Result:           &conf,
			WeaklyTypedInput: true,
		},
	}

	if err = k.UnmarshalWithConf("", &conf, unmarshalConf); err != nil {
		return config.Config{}, err
	}

	return conf, nil
}
