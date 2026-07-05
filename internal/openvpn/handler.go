package openvpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
)

var reMaskClientPassword = regexp.MustCompile(`CLIENT:ENV,password=(.*)\r?\n`)

const (
	clientWorkerCount     = 10
	clientWorkerQueueSize = 32
)

// handlePassword enters the password on the OpenVPN management interface connection.
func (c *Client) handlePassword(ctx context.Context) error {
	buf := make([]byte, 15)

	err := c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}

	_, err = io.ReadFull(c.conn, buf)
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
		if c.conf.OpenVPN.Password == "" {
			return errors.New("management password required")
		}

		if err = c.sendPassword(ctx); err != nil {
			return err
		}
	case c.conf.OpenVPN.Password != "":
		return errors.New("management password expected, but server does not ask for me")
	default:
		// In case there is no password, read the whole line
		c.scanner.Scan()
	}

	return nil
}

// sendPassword enters the password on the OpenVPN management interface connection.
func (c *Client) sendPassword(ctx context.Context) error {
	if err := c.rawCommand(ctx, c.conf.OpenVPN.Password.String(), "management-password"); err != nil {
		return fmt.Errorf("error from password command: %w", err)
	}

	buf := make([]byte, 15)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return fmt.Errorf("unable to read answer after sending password: %w", err)
	}

	if !strings.Contains("SUCCESS: password is correct", string(buf)) { //nolint:gocritic
		return ErrInvalidPassword
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

//nolint:cyclop
func (c *Client) handleMessage(ctx context.Context, message string) error {
	switch {
	case strings.HasPrefix(message, ">"):
		switch {
		case strings.HasPrefix(message, ">CLIEN"):
			return c.handleClientMessage(ctx, message)
		case strings.HasPrefix(message, ">HOLD:"):
			c.commandsCh <- "hold release"
		case strings.HasPrefix(message, ">INFO:"):
			// welcome message
			if strings.HasPrefix(message, ">INFO:OpenVPN Management Interface Version") {
				return nil
			}

			c.commandResponseCh <- message
		default:
			c.writeToPassThroughClient(message)
		}

	// SUCCESS: hold release succeeded
	case len(message) >= 13 && message[9:13] == "hold":
		c.logger.LogAttrs(ctx, slog.LevelInfo, "hold release succeeded")
	default:
		select {
		case c.commandResponseCh <- message:
		case <-time.After(2 * time.Second):
			c.logger.LogAttrs(ctx, slog.LevelWarn, "command response not accepted. Was there a timeout before? Dropping message", slog.String("message", message))
		}
	}

	return nil
}

func (c *Client) handleClientMessage(ctx context.Context, message string) error {
	c.logger.LogAttrs(ctx, slog.LevelDebug, reMaskClientPassword.ReplaceAllLiteralString(message, "CLIENT:ENV,password=***\r\n"))

	client, err := connection.NewClient(c.conf, message)
	if err != nil {
		return fmt.Errorf("error parsing client message: %w", err)
	}

	c.clientsCh <- client

	return nil
}

// handleClients receives new messages from clientsCh and processes them.
func (c *Client) handleClients(ctx context.Context, errCh chan<- error) {
	clientJobs := make([]chan connection.Client, clientWorkerCount)

	var (
		wg      sync.WaitGroup
		errOnce sync.Once
	)

	reportErr := func(err error) {
		errOnce.Do(func() {
			errCh <- err
		})
	}

	for i := range clientJobs {
		clientJobs[i] = make(chan connection.Client, clientWorkerQueueSize)

		wg.Go(func() {
			c.handleClientWorker(ctx, clientJobs[i], reportErr)
		})
	}

	defer func() {
		for _, clientJob := range clientJobs {
			close(clientJob)
		}

		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return // Error somewhere, terminate
		case client, ok := <-c.clientsCh:
			if !ok {
				return
			}

			workerIndex := client.CID % uint64(len(clientJobs))

			select {
			case clientJobs[workerIndex] <- client:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (c *Client) handleClientWorker(ctx context.Context, clients <-chan connection.Client, reportErr func(error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case client, ok := <-clients:
			if !ok {
				return
			}

			if err := c.processClient(ctx, client); err != nil {
				reportErr(err)

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

			if err := c.rawCommand(ctx, command, managementCommandName(command)); err != nil {
				errCh <- err

				return
			}
		}
	}
}
