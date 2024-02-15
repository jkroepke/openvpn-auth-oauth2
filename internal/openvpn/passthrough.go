package openvpn

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"time"
)

func (c *Client) handlePassthrough() {
	var (
		conn     net.Conn
		err      error
		listener net.Listener
	)

	switch c.conf.OpenVpn.Passthrough.Address.Scheme {
	case "tcp":
		listener, err = net.Listen(c.conf.OpenVpn.Passthrough.Address.Scheme, c.conf.OpenVpn.Passthrough.Address.Host)
	case "unix":
		listener, err = net.Listen(c.conf.OpenVpn.Passthrough.Address.Scheme, c.conf.OpenVpn.Passthrough.Address.Path)
	default:
		err = fmt.Errorf("%w %s", ErrUnknownProtocol, c.conf.OpenVpn.Addr.Scheme)
	}

	if err != nil {
		c.ctxCancel(fmt.Errorf("error setup openvpn management passthrough listener: %w", err))

		return
	}

	defer listener.Close()

	go func() {
		var (
			err     error
			message string
		)

		for {
			select {
			case <-c.ctx.Done():
				listener.Close()
				return // Error somewhere, terminate
			case message = <-c.passthroughCh:
				if message == "" {
					return
				}

				if conn == nil {
					continue
				}

				_ = conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))

				if _, err = conn.Write([]byte(message + "\n")); err != nil {
					c.logger.Warn(fmt.Errorf("unable to write message to client %s: %w", conn.RemoteAddr(), err).Error())

					return
				}
			}
		}
	}()

	for {
		// Listen for an incoming connection.
		conn, err = listener.Accept()
		if err != nil {
			c.ctxCancel(fmt.Errorf("error accepting: %w", err))

			return
		}

		c.handlePassthroughClient(conn)

		conn = nil
	}
}

func (c *Client) writeToPassthroughClient(message string) {
	if c.conf.OpenVpn.Passthrough.Enabled {
		c.passthroughCh <- message
	}
}

func (c *Client) handlePassthroughClient(conn net.Conn) {
	defer conn.Close()

	var err error

	logger := c.logger.With(slog.String("client", conn.RemoteAddr().String()))
	logger.Info("accepted connection")

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), bufio.MaxScanTokenSize)

	if c.conf.OpenVpn.Passthrough.Password.String() != "" {
		_, err = c.conn.Write([]byte("ENTER PASSWORD:"))
		if err != nil {
			logger.Warn(fmt.Errorf("unable to write to client: %w", err).Error())
			return
		}

		if !scanner.Scan() {
			if c.scanner.Err() != nil {
				logger.Warn(c.scanner.Err().Error())
			}

			return
		}

		if scanner.Text() != c.conf.OpenVpn.Passthrough.Password.String() {
			logger.Warn("client provide invalid password")
			return
		}
	}

	var buf bytes.Buffer

	buf.Grow(4096)

	errCh := make(chan error, 1)

	go func(errCh chan error) {
		for scanner.Scan() {
			line := scanner.Bytes()

			if bytes.HasPrefix(line, []byte("client-deny")) || bytes.HasPrefix(line, []byte("client-auth")) || bytes.HasPrefix(line, []byte("hold")) {
				c.writeToPassthroughClient("ERROR: command not allowed")
				logger.Warn("passthrough client send client-deny or client-auth message, ignoring...")

				continue
			}

			if bytes.HasPrefix(line, []byte("version")) {
				c.writeToPassthroughClient("OpenVPN Version: openvpn-auth-oauth2\nManagement Interface Version: 5\nEND\n")

				continue
			}

			if _, err := buf.Write(line); err != nil {
				errCh <- fmt.Errorf("unable to write string to buffer: %w", err)

				return
			}

			if _, err := buf.WriteString("\n"); err != nil {
				errCh <- fmt.Errorf("unable to newline to buffer: %w", err)

				return
			}
		}

		errCh <- c.scanner.Err()
	}(errCh)

	err = <-errCh
	if err != nil {
		logger.Warn(err.Error())
	}
}
