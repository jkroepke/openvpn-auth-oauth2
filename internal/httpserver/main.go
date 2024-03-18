package httpserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

type Server struct {
	name   string
	conf   config.HTTP
	logger *slog.Logger
	server *http.Server

	tlsCertificate   *tls.Certificate
	tlsCertificateMu sync.RWMutex
}

func NewHTTPServer(name string, logger *slog.Logger, conf config.HTTP, fnHandler *http.ServeMux) *Server {
	return &Server{
		name:   name,
		conf:   conf,
		logger: logger,
		server: &http.Server{
			Addr:              conf.Listen,
			ReadHeaderTimeout: 3 * time.Second,
			ReadTimeout:       3 * time.Second,
			WriteTimeout:      3 * time.Second,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
			Handler:           fnHandler,
		},
		tlsCertificateMu: sync.RWMutex{},
	}
}

func (s *Server) Listen(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	s.server.BaseContext = func(_ net.Listener) context.Context { return ctx }

	var errCh chan error

	if s.conf.TLS {
		s.logger.Info(fmt.Sprintf(
			"start HTTPS %s listener on %s", s.name, s.conf.Listen,
		))

		if err := s.Reload(); err != nil {
			return err
		}

		s.server.TLSConfig = new(tls.Config)
		s.server.TLSConfig.GetCertificate = s.GetCertificateFunc()

		go func() {
			errCh <- s.server.ListenAndServeTLS("", "")
		}()
	} else {
		s.logger.Info(fmt.Sprintf(
			"start HTTP %s listener on %s", s.name, s.conf.Listen,
		))

		go func() {
			errCh <- s.server.ListenAndServeTLS("", "")
		}()
	}

	select {
	case <-ctx.Done():
		s.logger.Info(fmt.Sprintf("start graceful shutdown of http %s listener", s.name))

		if err := s.shutdown(); err != nil { //nolint:contextcheck
			s.logger.Error(fmt.Errorf("error graceful shutdown %s: %w", s.name, err).Error())

			return nil
		}

		s.logger.Info(fmt.Sprintf("http %s listener successfully terminated", s.name))
	case err := <-errCh:
		return fmt.Errorf("error http %s listening: %w", s.name, err)
	}

	return nil
}

func (s *Server) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		s.tlsCertificateMu.RLock()
		defer s.tlsCertificateMu.RUnlock()

		return s.tlsCertificate, nil
	}
}

func (s *Server) Reload() error {
	if !s.conf.TLS {
		return nil
	}

	certs, err := tls.LoadX509KeyPair(s.conf.CertFile, s.conf.KeyFile)
	if err != nil {
		return fmt.Errorf("tls.LoadX509KeyPair: %w", err)
	}

	s.tlsCertificateMu.Lock()

	if s.tlsCertificate != nil {
		s.logger.Info("reloading TLS certificate")
	}

	s.tlsCertificate = &certs

	s.tlsCertificateMu.Unlock()

	return nil
}

func (s *Server) shutdown() error {
	if s.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx) //nolint:wrapcheck
}
