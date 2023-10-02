package openvpn

import (
	"fmt"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

// handlePassword enters the password on the OpenVPN management interface connection
func (c *Client) handlePassword() error {
	if err := c.rawCommand(utils.StringConcat(c.conf.OpenVpn.Password, "\n")); err != nil {
		return fmt.Errorf("error from password command: %w", err)
	}

	resp, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("unable to read messge from buffer: %w", err)
	}

	if !strings.Contains(resp, "SUCCESS: password is correct") {
		return fmt.Errorf("unable to connect to openvpn management interface: %w", ErrInvalidPassword)
	}

	return nil
}

// handleMessages handles all incoming messages and route messages to different channels
func (c *Client) handleMessages() {
	defer close(c.commandResponseCh)
	defer close(c.clientsCh)

	for {
		message, err := c.readMessage()
		if err != nil {
			c.errCh <- err

			return
		}

		if strings.HasPrefix(message, ">CLIENT:") {
			client, err := connection.NewClient(message)
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
	}
}

func (c *Client) handleClients() {
	var client connection.Client

	for {
		client = <-c.clientsCh
		if client.Reason == "" {
			return
		}

		if err := c.processClient(client); err != nil {
			c.errCh <- err

			return
		}
	}
}

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
