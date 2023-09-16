package cmd

import (
	"fmt"
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
)

var k = koanf.New(".")

func Execute() {
	zapConfig := zap.NewProductionConfig()
	zapConfig.Level = zap.NewAtomicLevel()
	logger, _ := zapConfig.Build()
	defer logger.Sync()

	f := config.FlagSet()
	if err := f.Parse(os.Args[1:]); err != nil {
		logger.Fatal(fmt.Sprintf("error loading config: %v", err))
	}

	configFile, _ := f.GetString("config")
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
	if err := k.UnmarshalWithConf("", &conf, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		logger.Fatal(fmt.Sprintf("error loading config: %v", err))
	}

	if err := config.Validate(&conf); err != nil {
		logger.Fatal(fmt.Sprintf("error validating config: %v", err))
	}

	level, err := zap.ParseAtomicLevel(conf.Log.Level)
	if err != nil {
		logger.Fatal(fmt.Sprintf("invalid log level: %v", err))
	}
	zapConfig.Level.SetLevel(level.Level())
	sugaredLogger := logger.Sugar()

	oidcClient, err := oauth2.Configure(&conf)
	if err != nil {
		sugaredLogger.Fatal(err)
	}

	openvpnClient := openvpn.NewClient(sugaredLogger, &conf)

	go func() {
		stdLogger, err := zap.NewStdLogAt(logger, zap.ErrorLevel)
		if err != nil {
			sugaredLogger.Fatal(err)
		}

		server := &http.Server{
			Addr:     conf.Http.Listen,
			ErrorLog: stdLogger,
			Handler:  oauth2.Handler(sugaredLogger, &oidcClient, &conf, openvpnClient),
		}

		if conf.Http.Tls {
			sugaredLogger.Infof("HTTPS server listen on %s", conf.Http.Listen)
			if err := server.ListenAndServeTLS(conf.Http.CertFile, conf.Http.KeyFile); err != nil {
				sugaredLogger.Fatal(err)
			}
		} else {
			sugaredLogger.Infof("HTTP server listen on %s", conf.Http.Listen)
			if err := server.ListenAndServe(); err != nil {
				sugaredLogger.Fatal(err)
			}
		}
	}()

	if err := openvpnClient.Connect(); err != nil {
		sugaredLogger.Fatal(err)
	}
}
