package openvpn

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

// handlePassword enters the password on the OpenVPN management interface connection.
func (c *Client) handlePassword() error {
	buf := make([]byte, 15)

	_, err := c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read first message: %w", err)
	}

	c.logger.Debug(utils.StringConcat("password probe: ", string(buf)))

	switch {
	case string(buf) == "ENTER PASSWORD:":
		if c.conf.OpenVpn.Password == "" {
			return errors.New("management password required")
		}

		if err = c.sendPassword(); err != nil {
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
func (c *Client) sendPassword() error {
	if err := c.rawCommand(c.conf.OpenVpn.Password.String()); err != nil {
		return fmt.Errorf("error from password command: %w", err)
	}

	var buf bytes.Buffer
	if err := c.readMessage(&buf); err != nil {
		return fmt.Errorf("readMessage: %w", err)
	}

	if !strings.Contains(buf.String(), "SUCCESS: password is correct") {
		return fmt.Errorf("unable to connect to openvpn management interface: %w", ErrInvalidPassword)
	}

	return nil
}

// handleMessages handles all incoming messages and route messages to different channels.
func (c *Client) handleMessages() {
	defer close(c.commandResponseCh)
	defer close(c.clientsCh)

	var (
		err     error
		buf     bytes.Buffer
		client  connection.Client
		message string
	)

	buf.Grow(4096)

	for {
		if err = c.readMessage(&buf); err != nil {
			if errors.Is(err, io.EOF) {
				c.logger.Warn("OpenVPN management interface connection terminated")
				c.Shutdown()

				return
			}

			c.shutdownMu.Lock()

			if !c.closed {
				c.errCh <- fmt.Errorf("error reading bytes: %w", err)
			}

			c.shutdownMu.Unlock()

			return
		}

		message = buf.String()

		switch {
		case strings.HasPrefix(message, ">CLIENT:"):
			client, err = connection.NewClient(c.conf, message)
			if err != nil {
				c.errCh <- err

				return
			}

			c.clientsCh <- client
		case strings.HasPrefix(message, ">HOLD:"):
			err = c.releaseManagementHold()
			if err != nil {
				c.errCh <- err

				return
			}
		case strings.HasPrefix(message, "SUCCESS:"):
			fallthrough
		case strings.HasPrefix(message, "ERROR:"):
			fallthrough
		case strings.HasPrefix(message, "OpenVPN Version:"):
			c.commandResponseCh <- message
		}

		buf.Reset()
	}
}

// handlePassword receive a new message from clientsCh and process them.
func (c *Client) handleClients() {
	var (
		client connection.Client
		err    error
	)

	for {
		client = <-c.clientsCh
		if client.Reason == "" {
			return
		}

		if err = c.processClient(client); err != nil {
			c.errCh <- err

			return
		}
	}
}

// handleCommands receive new command from commandsCh and send them to OpenVPN management interface.
func (c *Client) handleCommands() {
	var command string

	for {
		command = <-c.commandsCh
		if command == "" {
			return
		}

		if err := c.rawCommand(command); err != nil {
			c.errCh <- err

			return
		}
	}
}
