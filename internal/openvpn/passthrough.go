package openvpn

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

const writeTimeout = 20 * time.Millisecond

// handlePassthrough starts a listener for the passthrough interface. This allows the management interface to be
// accessed from a different network interface or even from a different machine.
// The passthrough interface is a simple text-based protocol that allows the client to send commands to the management
// interface and receive the responses.
// The passthrough interface is disabled by default. To enable it, set the passthrough.enabled option to true in the
// configuration file.
//
//nolint:cyclop,gocognit
func (c *Client) handlePassthrough() {
	var conn net.Conn

	c.logger.Info("start pass-through listener on " + c.conf.OpenVpn.Passthrough.Address.String())

	listener, closer, err := c.setupPassthroughListener()
	if err != nil {
		c.ctxCancel(fmt.Errorf("error setup openvpn management pass-through listener: %w", err))

		return
	}

	defer func() {
		defer closer()

		if r := recover(); r != nil {
			c.ctxCancel(fmt.Errorf("panic: %v", r))
		}
	}()

	connMu := sync.Mutex{}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logger.Warn(fmt.Errorf("panic: %v", r).Error())
			}
		}()

		var (
			err     error
			message string
		)

		for {
			select {
			case <-c.ctx.Done():
				c.logger.Info("shutdown OpenVPN pass-through connection")
				closer()

				connMu.Lock()

				if conn != nil {
					conn.Close()
				}

				connMu.Unlock()

				return // Error somewhere, terminate
			case message = <-c.passthroughCh:
				if message == "" || message == "\r\n" {
					return
				}

				connMu.Lock()
				if conn == nil {
					continue
				}

				_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))

				if _, err = conn.Write([]byte(message + "\r\n")); err != nil {
					connMu.Unlock()

					c.logger.Warn(fmt.Errorf("unable to write message to client %w", err).Error(), slog.String("client", conn.RemoteAddr().String()))

					return
				}

				connMu.Unlock()
			}
		}
	}()

	for {
		connMu.Lock()

		conn = nil
		// Listen for an incoming connection.
		conn, err = listener.Accept()

		connMu.Unlock()

		if err != nil {
			c.ctxCancel(fmt.Errorf("error accepting: %w", err))

			return
		}

		c.handlePassthroughClient(conn)
	}
}

func (c *Client) writeToPassthroughClient(message string) {
	if c.conf.OpenVpn.Passthrough.Enabled {
		c.passthroughCh <- message
	}
}

func (c *Client) handlePassthroughClient(conn net.Conn) {
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
	}

	logger.Info("pass-through: accepted connection")

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), bufio.MaxScanTokenSize)

	if err = c.handlePassthroughClientAuth(conn, scanner); err != nil {
		logger.Warn(err.Error())

		return
	}

	if err = c.handlePassthroughClientCommands(conn, logger, scanner); err != nil {
		logger.Warn(err.Error())
	}

	logger.Info("pass-through: closed connection")
}

func (c *Client) handlePassthroughClientCommands(conn net.Conn, logger *slog.Logger, scanner *bufio.Scanner) error {
	var (
		err  error
		line string
		resp string
	)

	for scanner.Scan() {
		line = scanner.Text()

		logger.LogAttrs(c.ctx, slog.LevelDebug, "received command", slog.String("command", line))

		switch {
		case strings.HasPrefix(line, "client-deny"), strings.HasPrefix(line, "client-auth"):
			c.writeToPassthroughClient("ERROR: command not allowed")
			logger.Warn("pass-through: client send client-deny or client-auth message, ignoring...")

			continue
		case strings.HasPrefix(line, "hold"):
			c.writeToPassthroughClient("SUCCESS: hold release succeeded")

			continue
		case strings.HasPrefix(line, "exit"), strings.HasPrefix(line, "quit"):
			conn.Close()

			return nil
		case line == "":
			continue
		}

		resp, err = c.SendCommand(line, true)
		if err != nil {
			logger.Warn(fmt.Errorf("pass-through: error from command '%s': %w", line, err).Error())
		} else {
			c.writeToPassthroughClient(strings.TrimSpace(resp))
		}
	}

	return fmt.Errorf("pass-through: unable to read from client: %w", c.scanner.Err())
}

func (c *Client) handlePassthroughClientAuth(conn net.Conn, scanner *bufio.Scanner) error {
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

	c.writeToPassthroughClient("SUCCESS: password is correct")

	return nil
}

func (c *Client) setupPassthroughListener() (net.Listener, func(), error) {
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

	if err := os.Chmod(c.conf.OpenVpn.Passthrough.Address.Path, os.FileMode(c.conf.OpenVpn.Passthrough.SocketMode)); err != nil {
		return fmt.Errorf("error chmod: %w", err)
	}

	return nil
}
