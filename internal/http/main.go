package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

type Server struct {
	conf   config.Config
	logger *slog.Logger
	server *http.Server
}

func NewHTTPServer(logger *slog.Logger, conf config.Config, fnHandler *http.ServeMux) Server {
	return Server{
		conf:   conf,
		logger: logger,
		server: &http.Server{
			Addr:              conf.HTTP.Listen,
			ReadHeaderTimeout: 3 * time.Second,
			ReadTimeout:       3 * time.Second,
			WriteTimeout:      3 * time.Second,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
			Handler:           fnHandler,
		},
	}
}

func (s Server) Listen() error {
	if s.server == nil {
		return nil
	}

	var err error

	if s.conf.HTTP.TLS {
		s.logger.Info(fmt.Sprintf(
			"start HTTPS server listener on %s with base url %s", s.conf.HTTP.Listen, s.conf.HTTP.BaseURL.String(),
		))

		err = s.server.ListenAndServeTLS(s.conf.HTTP.CertFile, s.conf.HTTP.KeyFile)
	} else {
		s.logger.Info(fmt.Sprintf(
			"start HTTP server listener on %s with base url %s", s.conf.HTTP.Listen, s.conf.HTTP.BaseURL.String(),
		))

		err = s.server.ListenAndServe()
	}

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("ListenAndServeTLS: %w", err)
	}

	return nil
}

func (s Server) Shutdown() error {
	if s.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx) //nolint:wrapcheck
}
