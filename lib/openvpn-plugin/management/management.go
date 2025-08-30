package management

import "C"
import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/version"
)

const writeTimeout = 1000 * time.Millisecond
const newline = "\r\n"

type Server struct {
	logger       *slog.Logger
	password     string
	listenSocket net.Listener
	connection   net.Conn
	connectionMu sync.Mutex
	connected    atomic.Int64

	respCh chan string
}

func NewServer(logger *slog.Logger, password string) *Server {
	return &Server{
		logger:   logger,
		password: password,
		respCh:   make(chan string, 1),
	}
}

func (s *Server) Listen(ctx context.Context, addr string) error {
	parsedURL, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid listen socket address '%s': %w", addr, err)
	} else if parsedURL.Scheme != "tcp" && parsedURL.Scheme != "unix" {
		return fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
	}

	var lc net.ListenConfig

	s.listenSocket, err = lc.Listen(ctx, parsedURL.Scheme, parsedURL.Host)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		for {
			connection, err := s.listenSocket.Accept()
			if err != nil {
				s.logger.Warn("error accepting connection",
					slog.Any("error", err),
				)

				return
			}

			if err := s.handleManagementClient(ctx, connection); err != nil {
				s.logger.Warn("error handling management client",
					slog.Any("error", err),
					slog.String("remote_addr", connection.RemoteAddr().String()),
				)
			}
		}
	}()

	return nil
}

func (s *Server) Close() {
	s.connectionMu.Lock()

	if s.connection != nil {
		_ = s.connection.Close()

		s.connection = nil
	}

	s.connectionMu.Unlock()

	if s.listenSocket != nil {
		if err := s.listenSocket.Close(); err != nil {
			s.logger.Error(fmt.Errorf("unable to close listen socket: %w", err).Error())
		}
	}
}

// handleManagementClient handles a single management client connection.
func (s *Server) handleManagementClient(ctx context.Context, conn net.Conn) error {
	s.connectionMu.Lock()
	s.connection = conn
	s.connectionMu.Unlock()
	s.connected.Store(1)

	defer func() {
		s.connectionMu.Lock()
		s.connection = nil
		s.connectionMu.Unlock()
		s.connected.Store(0)
	}()

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), bufio.MaxScanTokenSize)

	if err := s.handleManagementClientAuth(ctx, conn, scanner); err != nil {
		return err
	}

	_ = s.write(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
	s.connected.Store(1)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "quit"):
			fallthrough
		case strings.HasPrefix(line, "exit"):
			_ = s.write("SUCCESS: exiting")
			break
		case strings.HasPrefix(line, "hold release"):
			_ = s.write("SUCCESS: hold released")
		case strings.HasPrefix(line, "version"):
			_ = s.write(fmt.Sprintf("OpenVPN Version: openvpn-auth-oauth2 %s\nManagement Interface Version: 5\nEND", version.Version))
		case strings.HasPrefix(line, "help"):
			_ = s.write("SUCCESS: help")
		case strings.HasPrefix(line, "client-auth-nt"):
			fallthrough
		case strings.HasPrefix(line, "client-pending-auth"):
			fallthrough
		case strings.HasPrefix(line, "client-deny"):
			s.respCh <- line
		case strings.HasPrefix(line, "client-auth"):
			resp := line

			for scanner.Scan() {
				line = strings.TrimSpace(scanner.Text())
				resp += newline + line

				if line == "END" {
					break
				}
			}

			s.respCh <- resp // Fixed: send the complete response, not just the last line
		default:
			_ = s.write(fmt.Sprintf("UNKNOWN: %s", line))
		}
	}

	if err := scanner.Err(); err != nil {
		if err == io.EOF {
			return nil
		} else {
			return err
		}
	}

	_ = conn.Close()

	return nil
}

func (s *Server) handleManagementClientAuth(_ context.Context, conn net.Conn, scanner *bufio.Scanner) error {
	if s.password == "" {
		return nil
	}

	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("unable to set write deadline: %w", err)
	}

	_, err := conn.Write([]byte("ENTER PASSWORD:"))
	if err != nil {
		return fmt.Errorf("unable to write to client: %w", err)
	}

	if !scanner.Scan() {
		if err = scanner.Err(); err != nil {
			err = io.EOF
		}

		return fmt.Errorf("unable to read from client: %w", err)
	}

	if scanner.Text() != s.password {
		_ = s.write("ERROR: bad password")

		return errors.New("client provide invalid password")
	}

	return s.write("SUCCESS: password is correct")
}

func (s *Server) write(message string) error {
	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()

	if s.connected.Load() == 0 || s.connection == nil {
		return errors.New("no client connected")
	}

	if err := s.connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("unable to set write deadline: %w", err)
	}

	if _, err := s.connection.Write([]byte(message + "\r\n")); err != nil {
		return fmt.Errorf("unable to write to client: %w", err)
	}

	return nil
}

func (s *Server) ClientAuth(message string) (*Response, error) {
	if err := s.write(message); err != nil {
		return nil, err
	}

	select {
	case <-time.After(5 * time.Second):
		return nil, errors.New("timeout waiting for client response")
	case resp := <-s.respCh:
		return s.parseResponse(resp)
	}
}

type Response struct {
	ClientID     uint32
	ClientAuth   ClientAuth
	Message      string
	Timeout      string
	ClientConfig string
}

type ClientAuth int

const (
	ClientAuthAccept ClientAuth = iota
	ClientAuthDeny
	ClientAuthPending
)

func (s *Server) parseResponse(response string) (*Response, error) {
	cmd, rest, _ := strings.Cut(response, " ")
	clientIDStr, message, _ := strings.Cut(rest, " ")
	clientID, err := strconv.ParseUint(clientIDStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid client ID: %w", err)
	}

	switch cmd {
	case "client-auth-nt":
		// client-auth-nt 0 1
		return &Response{
			ClientID:   uint32(clientID),
			ClientAuth: ClientAuthAccept,
		}, nil
	case "client-accept":
		// client-auth 0 1
		// override-username "user"
		// END
		clientConfig := strings.Split(response, newline)

		return &Response{
			ClientID:     uint32(clientID),
			ClientAuth:   ClientAuthAccept,
			ClientConfig: strings.Join(clientConfig[1:len(clientConfig)-1], newline),
		}, nil
	case "client-deny":
		// client-deny 0 1 "OpenVPN Client does not support SSO authentication via webauth"
		return &Response{
			ClientID:   uint32(clientID),
			ClientAuth: ClientAuthDeny,
			Message:    message,
		}, nil
	case "client-pending-auth":
		// client-pending-auth 0 1 "WEB_AUTH::https://example.com/..." 300
		parts := strings.SplitN(message, " ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid client-pending-auth message: %s", message)
		}

		return &Response{
			ClientID:   uint32(clientID),
			ClientAuth: ClientAuthPending,
			Message:    strings.TrimPrefix(strings.Trim(parts[0], `"`), "WEB_AUTH::"),
			Timeout:    parts[1],
		}, nil
	default:
		return nil, fmt.Errorf("unknown response command: %s", cmd)
	}
}
