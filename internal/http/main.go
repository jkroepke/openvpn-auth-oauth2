package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

type Server struct {
	conf   config.Config
	logger *slog.Logger
	server *http.Server
}

func NewHTTPServer(logger *slog.Logger, conf config.Config, provider oauth2.Provider, openvpn oauth2.OpenVPN) Server {
	return Server{
		conf:   conf,
		logger: logger,
		server: &http.Server{
			Addr:              conf.HTTP.Listen,
			ReadHeaderTimeout: 3 * time.Second,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
			Handler:           oauth2.Handler(logger, conf, provider, openvpn),
		},
	}
}

func (s Server) Listen() error {
	if s.server == nil {
		return nil
	}

	if s.conf.HTTP.TLS {
		s.logger.Info(utils.StringConcat(
			"start HTTPS server listener on ", s.conf.HTTP.Listen, " with base url ", s.conf.HTTP.BaseURL.String(),
		))

		err := s.server.ListenAndServeTLS(s.conf.HTTP.CertFile, s.conf.HTTP.KeyFile)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("ListenAndServeTLS: %w", err)
		}

		return nil
	}

	s.logger.Info(utils.StringConcat(
		"start HTTP server listener on ", s.conf.HTTP.Listen, " with base url ", s.conf.HTTP.BaseURL.String(),
	))

	err := s.server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("ListenAndServe: %w", err)
	}

	return nil
}
func (s Server) Shutdown() error {
	if s.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}
