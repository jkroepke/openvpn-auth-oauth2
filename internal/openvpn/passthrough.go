package openvpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

const writeTimeout = 20 * time.Millisecond

// handlePassThrough starts a listener for the passthrough interface. This allows the management interface to be
// accessed from a different network interface or even from a different machine.
// The passthrough interface is a simple text-based protocol that allows the client to send commands to the management
// interface and receive the responses.
// The passthrough interface is disabled by default. To enable it, set the passthrough.enabled option to true in the
// configuration file.
//
//nolint:cyclop,gocognit
func (c *Client) handlePassThrough(ctx context.Context, errCh chan<- error) {
	var conn net.Conn

	listener, closer, err := c.setupPassThroughListener()
	if err != nil {
		errCh <- fmt.Errorf("error setup openvpn management pass-through listener: %w", err)

		return
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, fmt.Sprintf("start pass-through listener on %s://%s", listener.Addr().Network(), listener.Addr().String()))

	defer func() {
		defer closer()

		if r := recover(); r != nil {
			errCh <- fmt.Errorf("panic: %v; stack %s", r, debug.Stack())
		}
	}()

	connMu := sync.Mutex{}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logger.LogAttrs(ctx, slog.LevelError, "panic in handlePassThrough",
					slog.Any("err", r),
					slog.String("stack", string(debug.Stack())),
				)
			}
		}()

		var (
			err     error
			message string
			ok      bool
		)

		for {
			select {
			case <-ctx.Done():
				c.logger.LogAttrs(ctx, slog.LevelInfo, "shutdown OpenVPN pass-through connection")
				closer()

				return // Error somewhere, terminate
			case message, ok = <-c.passThroughCh:
				if !ok || message == "" || message == "\r\n" {
					continue
				}

				connMu.Lock()
				if conn == nil || c.passThroughConnected.Load() == 0 {
					connMu.Unlock()

					continue
				}

				_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))

				if _, err = conn.Write([]byte(message + "\r\n")); err != nil {
					remoteAddr := "<unknown>"
					if conn != nil {
						remoteAddr = conn.RemoteAddr().String()
					}

					c.logger.LogAttrs(ctx, slog.LevelWarn, fmt.Errorf("unable to write message to client %w", err).Error(), slog.String("client", remoteAddr))
				}

				connMu.Unlock()
			}
		}
	}()

	for {
		// Listen for an incoming connection.
		conn, err = listener.Accept()
		if err != nil {
			errCh <- fmt.Errorf("error accepting: %w", err)

			return
		}

		c.handlePassThroughClient(ctx, conn)

		c.passThroughConnected.Store(0)

		connMu.Lock()
		conn = nil
		connMu.Unlock()
	}
}

func (c *Client) writeToPassThroughClient(message string) {
	if c.conf.OpenVpn.Passthrough.Enabled {
		c.passThroughCh <- message
	}
}

func (c *Client) handlePassThroughClient(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var (
		err    error
		logger *slog.Logger
	)

	switch c.conf.OpenVpn.Passthrough.Address.Scheme {
	case SchemeTCP:
		logger = c.logger.With(slog.String("client", conn.RemoteAddr().String()))
	case SchemeUnix:
		logger = c.logger.With(slog.String("client", conn.RemoteAddr().Network()))
	default:
		panic(fmt.Errorf("%w %s", ErrUnknownProtocol, c.conf.OpenVpn.Passthrough.Address.Scheme))
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "pass-through: accepted connection")

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), bufio.MaxScanTokenSize)

	if err = c.handlePassThroughClientAuth(ctx, conn, scanner); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, err.Error())

		return
	}

	c.writeToPassThroughClient(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
	c.passThroughConnected.CompareAndSwap(0, 1)

	if err = c.handlePassThroughClientCommands(ctx, conn, logger, scanner); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, err.Error())
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "pass-through: closed connection")
}

func (c *Client) handlePassThroughClientCommands(ctx context.Context, conn net.Conn, logger *slog.Logger, scanner *bufio.Scanner) error {
	var (
		err  error
		line string
		resp string
	)

	for scanner.Scan() {
		line = strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		logger.LogAttrs(ctx, slog.LevelDebug, "received command", slog.String("command", line))

		switch {
		case strings.HasPrefix(line, "client-deny"), strings.HasPrefix(line, "client-auth"):
			c.writeToPassThroughClient("ERROR: command not allowed")
			logger.LogAttrs(ctx, slog.LevelWarn, "pass-through: client send client-deny or client-auth message, ignoring...")

			continue
		case line == "hold":
			c.writeToPassThroughClient("SUCCESS: hold release succeeded")

			continue
		case line == "exit", line == "quit":
			conn.Close()

			return nil
		}

		resp, err = c.SendCommand(line, true)
		if err != nil {
			logger.LogAttrs(ctx, slog.LevelWarn, fmt.Errorf("pass-through: error from command '%s': %w", line, err).Error())
		} else {
			c.writeToPassThroughClient(strings.TrimSpace(resp))
		}
	}

	if err = c.scanner.Err(); err != nil {
		return fmt.Errorf("pass-through: unable to read from client: %w", err)
	}

	return nil
}

func (c *Client) handlePassThroughClientAuth(_ context.Context, conn net.Conn, scanner *bufio.Scanner) error {
	if c.conf.OpenVpn.Passthrough.Password.String() == "" {
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
		if err = c.scanner.Err(); err != nil {
			err = io.EOF
		}

		return fmt.Errorf("pass-through: unable to read from client: %w", err)
	}

	if scanner.Text() != c.conf.OpenVpn.Passthrough.Password.String() {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = conn.Write([]byte("ERROR: bad password\r\n"))

		return errors.New("pass-through: client provide invalid password")
	}

	c.writeToPassThroughClient("SUCCESS: password is correct")

	return nil
}

func (c *Client) setupPassThroughListener() (net.Listener, func(), error) {
	var (
		err      error
		listener net.Listener
		closer   func()
	)

	switch c.conf.OpenVpn.Passthrough.Address.Scheme {
	case SchemeTCP:
		listener, err = net.Listen(c.conf.OpenVpn.Passthrough.Address.Scheme, c.conf.OpenVpn.Passthrough.Address.Host)
		if err != nil {
			return nil, nil, fmt.Errorf("error listen: %w", err)
		}

		closer = func() { listener.Close() }
	case SchemeUnix:
		listener, err = net.Listen(c.conf.OpenVpn.Passthrough.Address.Scheme, c.conf.OpenVpn.Passthrough.Address.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("error listen: %w", err)
		}

		if err = c.setupUNIXSocketPermissions(); err != nil {
			return nil, nil, err
		}

		closer = func() { listener.Close(); _ = os.Remove(c.conf.OpenVpn.Passthrough.Address.Path) }
	default:
		return nil, nil, fmt.Errorf("%w %s", ErrUnknownProtocol, c.conf.OpenVpn.Addr.Scheme)
	}

	return listener, closer, nil
}

func (c *Client) setupUNIXSocketPermissions() error {
	if c.conf.OpenVpn.Passthrough.SocketGroup != "" {
		gid, err := utils.LookupGroup(c.conf.OpenVpn.Passthrough.SocketGroup)
		if err != nil {
			return fmt.Errorf("error lookup group: %w", err)
		}

		if err = os.Chown(c.conf.OpenVpn.Passthrough.Address.Path, -1, gid); err != nil {
			return fmt.Errorf("error chown: %w", err)
		}
	}

	//nolint:gosec
	if err := os.Chmod(c.conf.OpenVpn.Passthrough.Address.Path, os.FileMode(c.conf.OpenVpn.Passthrough.SocketMode)); err != nil {
		return fmt.Errorf("error chmod: %w", err)
	}

	return nil
}
