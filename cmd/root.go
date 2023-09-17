package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

var k = koanf.New(".")

func Execute(version, commit, date string) {
	logger, _ := zap.NewProduction()
	defer logger.Sync() //nolint:errcheck

	f := config.FlagSet()
	if err := f.Parse(os.Args[1:]); err != nil {
		logger.Fatal(fmt.Sprintf("error parsing cli args: %v", err))
	}

	if versionFlag, _ := f.GetBool("version"); versionFlag {
		fmt.Printf("version: %s commit: %s date: %s", version, commit, date)
	}

	configFile, _ := f.GetString("configfile")
	if configFile != "" {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			logger.Fatal(fmt.Sprintf("error loading config: %v", err))
		}
	}

	if err := k.Load(posflag.Provider(f, ".", k), nil); err != nil {
		logger.Fatal(fmt.Sprintf("error loading config: %v", err))
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
		logger.Fatal(fmt.Sprintf("error loading config: %v", err))
	}

	var conf config.Config
	if err := k.Unmarshal("", &conf); err != nil {
		logger.Fatal(fmt.Sprintf("error loading config: %v", err))
	}

	logger, err := configureLogger(&conf)
	if err != nil {
		logger.Fatal(fmt.Sprintf("error configure logger: %v", err))
	}
	defer logger.Sync() //nolint:errcheck

	sl := slog.New(zapslog.NewHandler(logger.Core(), nil))

	if err := config.Validate(&conf); err != nil {
		sl.Error(fmt.Sprintf("error validating config: %v", err))
		os.Exit(1)
	}

	oidcClient, err := oauth2.NewProvider(sl, &conf)
	if err != nil {
		sl.Error(err.Error())
		os.Exit(1)
	}

	openvpnClient := openvpn.NewClient(sl, &conf)

	go func() {
		stdLogger, err := zap.NewStdLogAt(logger, zap.ErrorLevel)
		if err != nil {
			sl.Error(err.Error())
			os.Exit(1)
		}

		server := &http.Server{
			Addr:     conf.Http.Listen,
			ErrorLog: stdLogger,
			Handler:  oauth2.Handler(sl, &oidcClient, &conf, openvpnClient),
		}

		if conf.Http.Tls {
			sl.Info(fmt.Sprintf("HTTPS server listen on %s", conf.Http.Listen))
			if err := server.ListenAndServeTLS(conf.Http.CertFile, conf.Http.KeyFile); err != nil {
				sl.Error(err.Error())
				os.Exit(1)
			}
		} else {
			sl.Info(fmt.Sprintf("HTTP server listen on %s", conf.Http.Listen))
			if err := server.ListenAndServe(); err != nil {
				sl.Error(err.Error())
				os.Exit(1)
			}
		}
	}()

	if err := openvpnClient.Connect(); err != nil {
		sl.Error(err.Error())
		os.Exit(1)
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
