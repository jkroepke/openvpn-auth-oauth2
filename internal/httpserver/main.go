package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

type Server struct {
	conf   config.Config
	logger *slog.Logger
	server *http.Server

	tlsCertificate   *tls.Certificate
	tlsCertificateMu sync.RWMutex
}

func NewHTTPServer(logger *slog.Logger, conf config.Config, fnHandler *http.ServeMux) *Server {
	return &Server{
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
		tlsCertificateMu: sync.RWMutex{},
	}
}

func (s *Server) Listen() error {
	if s.server == nil {
		return nil
	}

	var err error

	if s.conf.HTTP.TLS {
		s.logger.Info(fmt.Sprintf(
			"start HTTPS server listener on %s with base url %s", s.conf.HTTP.Listen, s.conf.HTTP.BaseURL.String(),
		))

		if err = s.Reload(); err != nil {
			return err
		}

		s.server.TLSConfig = &tls.Config{
			GetCertificate: s.GetCertificateFunc(),
		}

		err = s.server.ListenAndServeTLS("", "")
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

func (s *Server) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		s.tlsCertificateMu.RLock()
		defer s.tlsCertificateMu.RUnlock()

		return s.tlsCertificate, nil
	}
}

func (s *Server) Reload() error {
	if !s.conf.HTTP.TLS {
		return nil
	}

	certs, err := tls.LoadX509KeyPair(s.conf.HTTP.CertFile, s.conf.HTTP.KeyFile)
	if err != nil {
		return fmt.Errorf("tls.LoadX509KeyPair: %w", err)
	}

	if s.tlsCertificate != nil {
		s.logger.Info("reloading TLS certificate")
	}

	s.tlsCertificateMu.Lock()

	s.tlsCertificate = &certs

	s.tlsCertificateMu.Unlock()

	return nil
}

func (s *Server) Shutdown() error {
	if s.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx) //nolint:wrapcheck
}
