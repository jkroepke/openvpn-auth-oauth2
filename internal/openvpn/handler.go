package openvpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
)

// handlePassword enters the password on the OpenVPN management interface connection.
func (c *Client) handlePassword(ctx context.Context) error {
	buf := make([]byte, 15)

	err := c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}

	_, err = c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("error probe password: %w", err)
	}

	err = c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}

	c.logger.LogAttrs(ctx, slog.LevelDebug, "password probe: "+string(buf))

	switch {
	case string(buf) == "ENTER PASSWORD:":
		if c.conf.OpenVpn.Password == "" {
			return errors.New("management password required")
		}

		if err = c.sendPassword(ctx); err != nil {
			return err
		}
	case c.conf.OpenVpn.Password != "":
		return errors.New("management password expected, but server does not ask for me")
	default:
		// In case there is no password, read the whole line
		c.scanner.Scan()
	}

	return nil
}

// sendPassword enters the password on the OpenVPN management interface connection.
func (c *Client) sendPassword(ctx context.Context) error {
	if err := c.rawCommand(ctx, c.conf.OpenVpn.Password.String()); err != nil {
		return fmt.Errorf("error from password command: %w", err)
	}

	buf := make([]byte, 15)
	if _, err := c.conn.Read(buf); err != nil {
		return fmt.Errorf("unable to read answer after sending password: %w", err)
	}

	if !strings.Contains("SUCCESS: password is correct", string(buf)) { //nolint:gocritic
		return fmt.Errorf("unable to connect to openvpn management interface: %w", ErrInvalidPassword)
	}

	// read the whole line
	c.scanner.Scan()

	return nil
}

// handleMessages handles all incoming messages and route messages to different channels.
func (c *Client) handleMessages(ctx context.Context, errCh chan<- error) {
	defer close(c.commandResponseCh)
	defer close(c.clientsCh)

	var (
		err error
		buf bytes.Buffer
	)

	buf.Grow(4096)

	for {
		if err = c.readMessage(&buf); err != nil {
			if errors.Is(err, io.EOF) {
				c.logger.LogAttrs(ctx, slog.LevelWarn, "OpenVPN management interface connection terminated")
				errCh <- nil

				return
			}

			errCh <- fmt.Errorf("error reading message: %w", err)

			return
		}

		if err = c.handleMessage(ctx, buf.String()); err != nil {
			errCh <- err

			return
		}
	}
}

func (c *Client) handleMessage(ctx context.Context, message string) error {
	if message[0] == '>' {
		switch message[0:6] {
		case ">CLIEN":
			return c.handleClientMessage(ctx, message)
		case ">HOLD:":
			c.commandsCh <- "hold release"
		case ">INFO:":
			// welcome message
			if strings.HasPrefix(message, ">INFO:OpenVPN Management Interface Version") {
				return nil
			}

			c.commandResponseCh <- message
		default:
			c.writeToPassThroughClient(message)
		}

		return nil
	}

	// SUCCESS: hold release succeeded
	if len(message) >= 13 && message[9:13] == "hold" {
		c.logger.LogAttrs(ctx, slog.LevelInfo, "hold release succeeded")

		return nil
	}

	c.commandResponseCh <- message

	return nil
}

func (c *Client) handleClientMessage(ctx context.Context, message string) error {
	c.logger.LogAttrs(ctx, slog.LevelDebug, message)

	client, err := connection.NewClient(c.conf, message)
	if err != nil {
		return fmt.Errorf("error parsing client message: %w", err)
	}

	c.clientsCh <- client

	return nil
}

// handlePassword receive a new message from clientsCh and process them.
func (c *Client) handleClients(ctx context.Context, errCh chan<- error) {
	var (
		client connection.Client
		ok     bool
		err    error
	)

	for {
		select {
		case <-ctx.Done():
			return // Error somewhere, terminate
		case client, ok = <-c.clientsCh:
			if !ok {
				return
			}

			if err = c.processClient(ctx, client); err != nil {
				errCh <- err

				return
			}
		}
	}
}

// handleCommands receive new command from commandsCh and send them to OpenVPN management interface.
func (c *Client) handleCommands(ctx context.Context, errCh chan<- error) {
	var (
		command string
		ok      bool
	)

	for {
		select {
		case <-ctx.Done():
			return // Error somewhere, terminate
		case command, ok = <-c.commandsCh:
			if !ok {
				return
			}

			if err := c.rawCommand(ctx, command); err != nil {
				errCh <- err

				return
			}
		}
	}
}
