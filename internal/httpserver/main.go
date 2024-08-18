package httpserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

const (
	ServerNameDefault = "server"
	ServerNameDebug   = "debug"
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

	errCh := make(chan error)

	if s.conf.TLS {
		if err := s.Reload(); err != nil {
			return err
		}

		s.server.TLSConfig = &tls.Config{
			GetCertificate: s.GetCertificateFunc(),
			NextProtos:     []string{"h2", "http/1.1"},
		}
	}

	go func() {
		errCh <- s.serve()
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("error http %s listening: %w", s.name, err)
	case <-ctx.Done():
		s.logger.Info(fmt.Sprintf("start graceful shutdown of http %s listener", s.name))

		if err := s.shutdown(); err != nil { //nolint:contextcheck
			s.logger.Error(fmt.Errorf("error graceful shutdown %s: %w", s.name, err).Error())

			return nil
		}

		s.logger.Info(fmt.Sprintf("http %s listener successfully terminated", s.name))
	}

	return nil
}

func (s *Server) serve() error {
	if s.server == nil {
		return fmt.Errorf("http %s server is nil", s.name)
	}

	var (
		err      error
		listener net.Listener
	)

	if s.name == ServerNameDefault && os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) {
		// systemd run
		listener, err = net.FileListener(os.NewFile(3, "from systemd"))
		if err != nil {
			return fmt.Errorf("net.FileListener: %w", err)
		}
	} else {
		listener, err = net.Listen("tcp", s.conf.Listen)
		if err != nil {
			return fmt.Errorf("net.Listen: %w", err)
		}
	}

	if s.conf.TLS {
		s.logger.Info(fmt.Sprintf(
			"start HTTPS %s listener on %s", s.name, listener.Addr().String(),
		))

		return s.server.ServeTLS(listener, "", "")
	}

	s.logger.Info(fmt.Sprintf(
		"start HTTP %s listener on %s", s.name, listener.Addr().String(),
	))

	return s.server.Serve(listener)
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
		return fmt.Errorf("http %s server is nil", s.name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	s.server.RegisterOnShutdown(cancel)

	return s.server.Shutdown(ctx) //nolint:wrapcheck
}
