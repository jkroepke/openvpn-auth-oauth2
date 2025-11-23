package management

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

const (
	writeTimeout = 1000 * time.Millisecond
	newline      = "\r\n"
)

type Server struct {
	listenSocket net.Listener
	connection   net.Conn
	logger       *slog.Logger
	respChs      map[uint64]chan *Response
	password     string
	connected    atomic.Int64
	respChMu     sync.Mutex
	listenMu     sync.Mutex
	connectionMu sync.Mutex
}

type Response struct {
	Message      string
	Timeout      string
	ClientConfig string
	ClientAuth   ClientAuth
	ClientID     uint32
}

type ClientAuth int

const (
	ClientAuthAccept ClientAuth = iota
	ClientAuthDeny
	ClientAuthPending
)

func (ca ClientAuth) String() string {
	switch ca {
	case ClientAuthAccept:
		return "ACCEPT"
	case ClientAuthDeny:
		return "DENY"
	case ClientAuthPending:
		return "PENDING"
	default:
		return "UNKNOWN"
	}
}

func NewServer(logger *slog.Logger, password string) *Server {
	return &Server{
		logger:   logger,
		password: password,
		respChs:  make(map[uint64]chan *Response, 1),
	}
}

func (s *Server) AuthPendingPoller(clientID uint64, timeout time.Duration) (*Response, error) {
	s.respChMu.Lock()

	if _, exists := s.respChs[clientID]; exists {
		s.respChMu.Unlock()

		return nil, fmt.Errorf("poller for client ID %d already exists", clientID)
	}

	respCh := make(chan *Response, 1)
	s.respChs[clientID] = respCh
	s.respChMu.Unlock()

	select {
	case <-time.After(timeout):
		s.respChMu.Lock()
		delete(s.respChs, clientID)
		s.respChMu.Unlock()

		return nil, errors.New("timeout waiting for client response")
	case resp := <-respCh:
		return resp, nil
	}
}

func (s *Server) ClientAuth(clientID uint64, message string) (*Response, error) {
	s.connectionMu.Lock()

	if s.connection == nil {
		s.connectionMu.Unlock()

		return nil, errors.New("no client connected")
	}

	s.connectionMu.Unlock()

	if err := s.writeToClient(message); err != nil {
		return nil, err
	}

	return s.AuthPendingPoller(clientID, 5*time.Second)
}

func (s *Server) ClientDisconnect(message string) error {
	s.connectionMu.Lock()

	if s.connection == nil {
		s.connectionMu.Unlock()

		return errors.New("no client connected")
	}

	s.connectionMu.Unlock()

	return s.writeToClient(message)
}

//nolint:cyclop
func (s *Server) Listen(ctx context.Context, addr string) error {
	parsedURL, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid listen socket address '%s': %w", addr, err)
	}

	var listenConfig net.ListenConfig

	switch parsedURL.Scheme {
	case "tcp":
		s.connectionMu.Lock()
		s.listenSocket, err = listenConfig.Listen(ctx, parsedURL.Scheme, parsedURL.Host)
		s.connectionMu.Unlock()
	case "unix":
		s.connectionMu.Lock()
		s.listenSocket, err = listenConfig.Listen(ctx, parsedURL.Scheme, parsedURL.Path)
		s.connectionMu.Unlock()
	default:
		return fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
	}

	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		for {
			s.connectionMu.Lock()
			listenSocket := s.listenSocket
			s.connectionMu.Unlock()

			if s.listenSocket == nil {
				return
			}

			connection, err := listenSocket.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					s.logger.Warn("error accepting connection",
						slog.Any("error", err),
					)
				}

				return
			}

			s.logger.InfoContext(ctx, "accepted new management client connection",
				slog.String("remote_addr", connection.RemoteAddr().String()),
			)

			if err := s.handleManagementClient(ctx, connection); err != nil {
				s.logger.WarnContext(ctx, "error handling management client",
					slog.Any("error", err),
					slog.String("remote_addr", connection.RemoteAddr().String()),
				)
			}

			s.logger.InfoContext(ctx, "management client disconnected",
				slog.String("remote_addr", connection.RemoteAddr().String()),
			)
		}
	}()

	return nil
}

func (s *Server) Close() {
	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()

	if s.connection != nil {
		_ = s.connection.Close()

		s.connection = nil
	}

	s.listenMu.Lock()
	defer s.listenMu.Unlock()

	if s.listenSocket != nil {
		if err := s.listenSocket.Close(); err != nil {
			s.logger.Error(fmt.Errorf("unable to close listen socket: %w", err).Error())
		}

		s.listenSocket = nil
	}
}

// handleManagementClient handles a single management client connection.
//
//nolint:cyclop
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

	_ = s.writeToClient(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
	s.connected.Store(1)

scan:
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "quit"):
			fallthrough
		case strings.HasPrefix(line, "exit"):
			_ = s.writeToClient("SUCCESS: exiting")

			break scan
		case strings.HasPrefix(line, "hold release"):
			_ = s.writeToClient("SUCCESS: hold released")

			continue
		case strings.HasPrefix(line, "version"):
			_ = s.writeToClient(fmt.Sprintf("OpenVPN Version: openvpn-auth-oauth2 %s\nManagement Interface Version: 5\nEND", version.Version))

			continue
		case strings.HasPrefix(line, "help"):
			_ = s.writeToClient("SUCCESS: help")

			continue
		case strings.HasPrefix(line, "client-auth-nt"):
			_ = s.writeToClient("SUCCESS: client-auth command succeeded")
		case strings.HasPrefix(line, "client-pending-auth"):
			_ = s.writeToClient("SUCCESS: client-pending-auth command succeeded")
		case strings.HasPrefix(line, "client-deny"):
			_ = s.writeToClient("SUCCESS: client-deny command succeeded")
		case strings.HasPrefix(line, "client-auth"):
			for scanner.Scan() {
				line += newline + strings.TrimSpace(scanner.Text())

				if strings.HasSuffix(line, "END") {
					break
				}
			}

			_ = s.writeToClient("SUCCESS: client-auth command succeeded")
		default:
			_ = s.writeToClient("ERROR: unknown command, enter 'help' for more options")

			continue
		}

		s.logger.DebugContext(ctx, line)

		resp, err := s.parseResponse(line)
		if err != nil {
			s.logger.ErrorContext(ctx, "unable to parse client response",
				slog.Any("err", err),
				slog.String("response", line),
			)
		}

		s.respChMu.Lock()
		respCh, exists := s.respChs[uint64(resp.ClientID)]
		delete(s.respChs, uint64(resp.ClientID))
		s.respChMu.Unlock()

		if exists {
			respCh <- resp
		}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}

		return err //nolint:wrapcheck
	}

	_ = conn.Close()

	return nil
}

func (s *Server) handleManagementClientAuth(_ context.Context, conn net.Conn, scanner *bufio.Scanner) error {
	if s.password == "" {
		return nil
	}

	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("unable to set writeToClient deadline: %w", err)
	}

	_, err := conn.Write([]byte("ENTER PASSWORD:"))
	if err != nil {
		return fmt.Errorf("unable to writeToClient to client: %w", err)
	}

	if !scanner.Scan() {
		if err = scanner.Err(); err == nil {
			err = io.EOF
		}

		return fmt.Errorf("unable to read from client: %w", err)
	}

	if scanner.Text() != s.password {
		_ = s.writeToClient("ERROR: bad password")

		return errors.New("client provide invalid password")
	}

	return s.writeToClient("SUCCESS: password is correct")
}

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
	case "client-auth":
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
		parts := strings.SplitN(message, " ", 2)

		var denyReason string
		if len(parts) == 2 {
			denyReason = strings.Trim(parts[1], `"`)
		} else {
			denyReason = "access denied"
		}

		return &Response{
			ClientID:   uint32(clientID),
			ClientAuth: ClientAuthDeny,
			Message:    denyReason,
		}, nil
	case "client-pending-auth":
		// client-pending-auth 0 1 "WEB_AUTH::https://example.com/..." 300
		parts := strings.SplitN(message, " ", 3)
		if len(parts) != 3 {
			return &Response{
				ClientID:   uint32(clientID),
				ClientAuth: ClientAuthDeny,
				Message:    "internal error",
			}, fmt.Errorf("invalid client-pending-auth message: %s", message)
		}

		return &Response{
			ClientID:   uint32(clientID),
			ClientAuth: ClientAuthPending,
			Message:    strings.Trim(parts[1], `"`),
			Timeout:    parts[2],
		}, nil
	default:
		return &Response{
			ClientID:   uint32(clientID),
			ClientAuth: ClientAuthDeny,
			Message:    "internal error",
		}, fmt.Errorf("unknown response command: %s", cmd)
	}
}

func (s *Server) writeToClient(message string) error {
	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()

	if s.connected.Load() == 0 || s.connection == nil {
		return errors.New("no client connected")
	}

	if err := s.connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("unable to set writeToClient deadline: %w", err)
	}

	if _, err := s.connection.Write([]byte(message + "\r\n")); err != nil {
		return fmt.Errorf("unable to writeToClient to client: %w", err)
	}

	return nil
}
