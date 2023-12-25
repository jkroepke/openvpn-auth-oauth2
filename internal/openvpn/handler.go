package openvpn

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

// handlePassword enters the password on the OpenVPN management interface connection.
func (c *Client) handlePassword() error {
	buf := make([]byte, 5)

	_, err := c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read first message: %w", err)
	}

	c.logger.Debug(utils.StringConcat("password probe: ", string(buf)))

	if string(buf) == "ENTER" {
		if c.conf.OpenVpn.Password == "" {
			return errors.New("management password required")
		}

		if err = c.sendPassword(); err != nil {
			return err
		}
	} else if c.conf.OpenVpn.Password != "" {
		return errors.New("management password expected, but server does not ask for me")
	}

	return nil
}

// sendPassword enters the password on the OpenVPN management interface connection.
func (c *Client) sendPassword() error {
	if err := c.rawCommand(utils.StringConcat(c.conf.OpenVpn.Password.String(), "\n")); err != nil {
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
			c.errCh <- fmt.Errorf("readMessage: %w", err)

			return
		}

		message = buf.String()

		if strings.HasPrefix(message, ">CLIENT:") {
			client, err = connection.NewClient(message)
			if err != nil {
				c.errCh <- err

				return
			}

			c.clientsCh <- client
		} else if strings.HasPrefix(message, "SUCCESS:") ||
			strings.HasPrefix(message, "ERROR:") ||
			strings.HasPrefix(message, "OpenVPN Version:") {
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
