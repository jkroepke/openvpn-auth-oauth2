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
	// This handler is the sole producer and owns closing both channels.
	defer close(c.commandResponseCh)
	defer close(c.clientsCh)

	var buf bytes.Buffer

	buf.Grow(4096)

	for {
		messageType, err := c.readMessage(&buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.logger.LogAttrs(ctx, slog.LevelWarn, "OpenVPN management interface connection terminated")

				errCh <- nil

				return
			}

			errCh <- fmt.Errorf("error reading message: %w", err)

			return
		}

		if err = c.handleMessage(ctx, messageType, buf.String()); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				errCh <- nil

				return
			}

			if c.closed.Load() == 1 && errors.Is(err, ErrConnectionTerminated) {
				errCh <- nil

				return
			}

			errCh <- err

			return
		}
	}
}

//nolint:cyclop
func (c *Client) handleMessage(ctx context.Context, messageType connection.MessageType, message string) error {
	switch messageType { //nolint:exhaustive // other real-time notifications are forwarded to the pass-through client
	case connection.MessageTypeClient:
		return c.handleClientMessage(ctx, message)
	case connection.MessageTypeClientAddress:
		c.handleClientAddressMessage(ctx, message)
	case connection.MessageTypeHold:
		select {
		case c.commandsCh <- "hold release":
		case <-ctx.Done():
			return fmt.Errorf("enqueue hold release: %w", ctx.Err())
		case <-c.shutdownCh:
			return ErrConnectionTerminated
		}
	case connection.MessageTypeInfo:
		// welcome message
		if strings.HasPrefix(message, ">INFO:OpenVPN Management Interface Version") {
			return nil
		}

		select {
		case c.commandResponseCh <- message:
		case <-ctx.Done():
			return fmt.Errorf("dispatch info response: %w", ctx.Err())
		case <-c.shutdownCh:
			return ErrConnectionTerminated
		}
	case connection.MessageTypeSuccess, connection.MessageTypeError, connection.MessageTypeResponse:
		return c.handleCommandResponse(ctx, messageType, message)
	case connection.MessageTypeUnknown:
		c.logger.LogAttrs(ctx, slog.LevelWarn, "unknown message from OpenVPN management interface", slog.String("message", strings.TrimSpace(message)))
		c.writeToPassThroughClient(message)
	default:
		c.writeToPassThroughClient(message)
	}

	return nil
}

func (c *Client) handleCommandResponse(ctx context.Context, messageType connection.MessageType, message string) error {
	// The hold release command is sent by handleMessage itself, nobody waits for its response.
	// OpenVPN responds with "SUCCESS: hold release succeeded", the plugin with "SUCCESS: hold released".
	if messageType == connection.MessageTypeSuccess && strings.HasPrefix(message, "SUCCESS: hold release") {
		c.logger.LogAttrs(ctx, slog.LevelInfo, "hold release succeeded")

		return nil
	}

	select {
	case c.commandResponseCh <- message:
	case <-ctx.Done():
		return fmt.Errorf("dispatch command response: %w", ctx.Err())
	case <-c.shutdownCh:
		return ErrConnectionTerminated
	case <-time.After(2 * time.Second):
		c.logger.LogAttrs(ctx, slog.LevelWarn, "command response not accepted. Was there a timeout before? Dropping message", slog.String("message", message))
	}

	return nil
}

// handleClientAddressMessage remembers the primary VPN address of a client.
// OpenVPN sends >CLIENT:ADDRESS right before >CLIENT:ESTABLISHED of the same client.
func (c *Client) handleClientAddressMessage(ctx context.Context, message string) {
	cid, addr, primary, err := connection.ParseClientAddress(message)
	if err != nil {
		c.logger.LogAttrs(ctx, slog.LevelWarn, "unable to parse client address message", slog.Any("err", err))

		return
	}

	if c.logger.Enabled(ctx, slog.LevelDebug) {
		c.logger.LogAttrs(ctx, slog.LevelDebug, "client address learned",
			slog.Uint64("cid", cid),
			slog.String("vpn_ip", addr),
			slog.Bool("primary", primary),
		)
	}

	// OpenVPN announces the IPv4 address before the IPv6 address. Keep the first one.
	if primary && (c.pendingClientAddress.cid != cid || c.pendingClientAddress.addr == "") {
		c.pendingClientAddress = clientAddress{cid: cid, addr: addr}
	}
}

func (c *Client) handleClientMessage(ctx context.Context, message string) error {
	if c.logger.Enabled(ctx, slog.LevelDebug) {
		c.logger.LogAttrs(ctx, slog.LevelDebug, reMaskClientPassword.ReplaceAllLiteralString(message, "CLIENT:ENV,password=***\r\n"))
	}

	client, err := connection.NewClient(c.conf, message)
	if err != nil {
		return fmt.Errorf("error parsing client message: %w", err)
	}

	if client.Reason == "ESTABLISHED" && c.pendingClientAddress.cid == client.CID {
		client.VPNAddress = c.pendingClientAddress.addr
	}

	c.pendingClientAddress = clientAddress{}

	select {
	case c.clientsCh <- client:
	case <-ctx.Done():
		return fmt.Errorf("enqueue client event: %w", ctx.Err())
	case <-c.shutdownCh:
		return ErrConnectionTerminated
	}

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

			// Count before the send so a fast worker cannot dequeue first.
			c.metrics.ClientQueued()

			select {
			case clientJobs[workerIndex] <- client:
			case <-ctx.Done():
				c.metrics.ClientDequeued()

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

			c.metrics.ClientDequeued()

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
		case <-c.shutdownCh:
			return
		case command, ok = <-c.commandsCh:
			if !ok {
				return
			}

			if err := c.rawCommand(ctx, command, managementCommandName(command)); err != nil {
				if c.closed.Load() == 1 {
					return
				}

				errCh <- err

				return
			}
		}
	}
}
