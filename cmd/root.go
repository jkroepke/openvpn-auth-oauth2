package cmd

import (
	"fmt"
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
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

var k = koanf.New(".")

func Execute(version, commit, date string) int {
	logger, _ := zap.NewProduction()
	defer logger.Sync() //nolint:errcheck

	f := config.FlagSet()
	if err := f.Parse(os.Args[1:]); err != nil {
		logger.Error(utils.StringConcat("error parsing cli args: ", err.Error()))
		return 1
	}

	if versionFlag, _ := f.GetBool("version"); versionFlag {
		fmt.Printf("version: %s\ncommit: %s\ndate: %s\ngo: %s\n", version, commit, date, runtime.Version())
		return 0
	}

	configFile, _ := f.GetString("config")
	if configFile != "" {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			logger.Error(utils.StringConcat("error loading config: ", err.Error()))
			return 1
		}
	}

	if err := k.Load(posflag.Provider(f, ".", k), nil); err != nil {
		logger.Error(utils.StringConcat("error loading config: ", err.Error()))
		return 1
	}

	if err := k.Load(env.ProviderWithValue("CONFIG_", ".", func(s string, v string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(s, "CONFIG_")), "_", ".", -1)

		// If there is a space in the value, split the value into a slice by the space.
		if strings.Contains(v, " ") {
			return key, strings.Split(v, " ")
		}

		// Otherwise, return the plain string.
		return key, v
	}), nil); err != nil {
		logger.Error(utils.StringConcat("error loading config: ", err.Error()))
		return 1
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

	if err := k.UnmarshalWithConf("", &conf, unmarshalConf); err != nil {
		logger.Error(utils.StringConcat("error loading config: ", err.Error()))
		return 1
	}

	logger, err := configureLogger(&conf)
	if err != nil {
		logger.Error(utils.StringConcat("error configure logger: ", err.Error()))
		return 1
	}
	defer logger.Sync() //nolint:errcheck

	sl := slog.New(zapslog.NewHandler(logger.Core(), nil))

	if err := config.Validate(&conf); err != nil {
		sl.Error(utils.StringConcat("error validating config: ", err.Error()))
		return 1
	}

	oidcClient, err := oauth2.NewProvider(sl, &conf)
	if err != nil {
		sl.Error(err.Error())
		return 1
	}

	openvpnClient := openvpn.NewClient(sl, &conf)
	done := make(chan int, 1)

	go func() {
		stdLogger, err := zap.NewStdLogAt(logger, zap.ErrorLevel)
		if err != nil {
			sl.Error(err.Error())
			done <- 1
		}

		server := &http.Server{
			Addr:     conf.Http.Listen,
			ErrorLog: stdLogger,
			Handler:  oauth2.Handler(sl, oidcClient, &conf, openvpnClient),
		}

		if conf.Http.Tls {
			sl.Info(utils.StringConcat("HTTPS server listen on ", conf.Http.Listen, " with base url ", conf.Http.BaseUrl.String()))
			if err := server.ListenAndServeTLS(conf.Http.CertFile, conf.Http.KeyFile); err != nil {
				sl.Error(err.Error())
				done <- 1
			}
		} else {
			sl.Info(utils.StringConcat("HTTP server listen on ", conf.Http.Listen, " with base url ", conf.Http.BaseUrl.String()))
			if err := server.ListenAndServe(); err != nil {
				sl.Error(err.Error())
				done <- 1
			}
		}
	}()

	go func() {
		defer openvpnClient.Shutdown()
		if err := openvpnClient.Connect(); err != nil {
			sl.Error(err.Error())
			done <- 1
		}
		done <- 0
	}()

	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case returnCode := <-done:
		return returnCode
	case sig := <-termCh:
		sl.Info(utils.StringConcat("receiving signal: ", sig.String()))
		openvpnClient.Shutdown()
		return 0
	}
}

func configureLogger(conf *config.Config) (*zap.Logger, error) {
	level, err := zap.ParseAtomicLevel(conf.Log.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %v", err)
	}

	zapConfig := zap.NewProductionConfig()
	zapConfig.Level = level
	zapConfig.Encoding = conf.Log.Format

	return zapConfig.Build()
}
