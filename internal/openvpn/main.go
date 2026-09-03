package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
)

// minManagementInterfaceVersion defines the minimum supported version of the
// OpenVPN management interface.
const minManagementInterfaceVersion = 5

const (
	managementVersionPrefix       = "Management Version: "
	managementPluginVersionPrefix = "OpenVPN Version: openvpn-auth-oauth2"
)

const WelcomeBanner = ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info"

// New creates a new Client configured with the provided logger and
// configuration.
func New(logger *slog.Logger, conf *config.Config) *Client {
	client := &Client{
		conf:   conf,
		logger: logger,

		connMu: sync.Mutex{},

		commandsBuffer: bytes.Buffer{},

		clientsCh:         make(chan connection.Client, 10),
		commandLock:       make(chan struct{}, 1),
		commandResponseCh: make(chan string),
		commandTimer:      time.NewTimer(conf.OpenVPN.CommandTimeout),
		commandsCh:        make(chan string, 10),
		passThroughCh:     make(chan string, 10),
		shutdownCh:        make(chan struct{}),
	}

	client.commandsBuffer.Grow(512)

	client.commandLock <- struct{}{}

	client.commandTimer.Stop()

	return client
}

// SetOAuth2Client assigns the OAuth2 client used for token refresh and
// disconnect callbacks.
func (c *Client) SetOAuth2Client(client oauth2Client) {
	c.oauth2 = client
}

// Connect establishes the management interface connection and starts the
// internal handlers. The call blocks until the context is cancelled or the
// connection terminates.
//
//nolint:cyclop
func (c *Client) Connect(ctx context.Context) error {
	var err error

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	c.ctxCancel = cancel

	c.logger.LogAttrs(ctx, slog.LevelInfo, "connect to openvpn management interface "+c.conf.OpenVPN.Addr.String())

	if err = c.setupConnection(ctx); err != nil {
		return fmt.Errorf("unable to connect to openvpn management interface %s: %w", c.conf.OpenVPN.Addr.String(), err)
	}

	c.scanner = bufio.NewScanner(c.conn)
	c.scanner.Split(bufio.ScanLines)
	c.scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), bufio.MaxScanTokenSize)

	if err = c.handlePassword(ctx); err != nil {
		_ = c.conn.Close()

		return fmt.Errorf("unable to authenticate with OpenVPN management interface: %w", err)
	}

	defer c.Shutdown(ctx)

	errChMessages := make(chan error, 1)
	errChClients := make(chan error, 1)
	errChCommands := make(chan error, 1)
	errChPassThrough := make(chan error, 1)

	go c.handleMessages(ctx, errChMessages)
	go c.handleClients(ctx, errChClients)
	go c.handleCommands(ctx, errChCommands)

	c.logger.LogAttrs(ctx, slog.LevelInfo, "connection to OpenVPN management interface established")

	if c.conf.OpenVPN.Passthrough.Enabled {
		go c.handlePassThrough(ctx, errChPassThrough)
	}

	if err := c.checkManagementInterfaceVersion(ctx); err != nil {
		if errors.Is(err, ErrConnectionTerminated) {
			return nil
		}

		return fmt.Errorf("unable to check OpenVPN management interface version: %w", err)
	}

	select {
	case <-ctx.Done():
		c.Shutdown(ctx)
	case err = <-errChMessages:
		if err != nil {
			err = fmt.Errorf("error handling messages: %w", err)
		}
	case err = <-errChClients:
		if err != nil {
			err = fmt.Errorf("error handling clients: %w", err)
		}
	case err = <-errChCommands:
		if err != nil {
			err = fmt.Errorf("error handling commands: %w", err)
		}
	case err = <-errChPassThrough:
		if err != nil {
			err = fmt.Errorf("error handling passthrough: %w", err)
		}
	}

	if err != nil {
		return fmt.Errorf("openvpn management error: %w", err)
	}

	return nil
}

// setupConnection dials the OpenVPN management interface and stores the
// resulting connection on the Client.
func (c *Client) setupConnection(ctx context.Context) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	var err error

	dialer := &net.Dialer{Timeout: 1 * time.Second}

	switch c.conf.OpenVPN.Addr.Scheme {
	case SchemeTCP:
		c.conn, err = dialer.DialContext(ctx, c.conf.OpenVPN.Addr.Scheme, c.conf.OpenVPN.Addr.Host)
	case SchemeUnix:
		c.conn, err = dialer.DialContext(ctx, c.conf.OpenVPN.Addr.Scheme, c.conf.OpenVPN.Addr.Path)
	default:
		err = fmt.Errorf("unable to connect to openvpn management interface: %w %s", ErrUnknownProtocol, c.conf.OpenVPN.Addr.Scheme)
	}

	return err
}

// checkManagementInterfaceVersion verifies that the management interface meets
// the minimum required version.
func (c *Client) checkManagementInterfaceVersion(ctx context.Context) error {
	resp, err := c.SendCommand(ctx, "version", false)
	if resp == "" {
		return nil
	}

	if err != nil {
		return fmt.Errorf("error from version command: %w", err)
	}

	if !strings.HasPrefix(resp, "OpenVPN Version: ") {
		return fmt.Errorf("error from version command: %w: %s", ErrErrorResponse, resp)
	}

	versionParts := strings.Split(resp, "\r\n")

	if len(versionParts) != 4 {
		return fmt.Errorf("%w: %s", ErrUnexpectedResponseFromVersionCommand, resp)
	}

	c.logger.LogAttrs(ctx, slog.LevelInfo, strings.Join(versionParts[0:1], " - "))

	if c.conf.OpenVPN.EnforceUniqueUser && strings.HasPrefix(versionParts[0], managementPluginVersionPrefix) {
		return ErrEnforceUniqueUserUnsupported
	}

	managementInterfaceVersion, err := parseManagementInterfaceVersion(versionParts[1])
	if err != nil {
		return err
	}

	// Management Interface Version 5 is required at minimum
	// ref: https://github.com/OpenVPN/openvpn/commit/a261e173341f8e68505a6ab5a413d09b0797a459
	if managementInterfaceVersion < minManagementInterfaceVersion {
		return ErrRequireManagementInterfaceVersion5
	}

	return nil
}

func parseManagementInterfaceVersion(versionLine string) (int, error) {
	prefix, version, found := strings.Cut(versionLine, managementVersionPrefix)
	if !found || prefix != "" {
		return 0, fmt.Errorf("%w: %s", ErrUnexpectedResponseFromVersionCommand, versionLine)
	}

	managementInterfaceVersion, err := strconv.Atoi(version)
	if err != nil {
		return 0, fmt.Errorf("unable to parse openvpn management interface version: %w", err)
	}

	return managementInterfaceVersion, nil
}

// checkClientSsoCapabilities reports whether the given client supports SSO via
// the webauth protocol.
func (c *Client) checkClientSsoCapabilities(client connection.Client) bool {
	return strings.Contains(client.IvSSO, "webauth")
}

// Shutdown closes the management connection and stops command processing.
func (c *Client) Shutdown(ctx context.Context) {
	if !c.closed.CompareAndSwap(0, 1) {
		return
	}

	// commandsCh has multiple producers and is intentionally left open;
	// shutdownCh owns lifecycle signaling.
	close(c.shutdownCh)

	c.logger.LogAttrs(ctx, slog.LevelInfo, "shutdown OpenVPN management connection")

	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// SendCommand sends a command to the management interface and waits for its
// response. When passthrough is true the raw response is returned without any
// validation. A rejected command returns the raw response together with a
// [ManagementCommandError].
func (c *Client) SendCommand(ctx context.Context, cmd string, passthrough bool) (string, error) {
	if cmd == "\x00" || c.closed.Load() == 1 {
		return "", nil
	}

	commandName := managementCommandForError(cmd, passthrough)

	if err := c.waitForCommandLock(ctx); err != nil {
		return "", fmt.Errorf("command error '%s': %w", commandName, err)
	}

	releaseCommandLock := true
	defer func() {
		if releaseCommandLock {
			c.commandLock <- struct{}{}
		}
	}()

	if c.closed.Load() == 1 {
		return "", ErrConnectionTerminated
	}

	if err := c.enqueueCommand(ctx, cmd); err != nil {
		return "", fmt.Errorf("command error '%s': %w", commandName, err)
	}

	// commandLock serializes resets and receives on the reusable timer.
	c.commandTimer.Reset(c.conf.OpenVPN.CommandTimeout)

	stopCommandTimer := true
	defer func() {
		if stopCommandTimer {
			c.commandTimer.Stop()
		}
	}()

	resp, canceled, err := c.waitForCommandResponse(ctx, commandName, passthrough)
	if canceled {
		releaseCommandLock = false
		stopCommandTimer = false

		go c.discardCommandResponse()
	}

	return resp, err
}

func (c *Client) waitForCommandLock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("wait for command lock: %w", err)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("wait for command lock: %w", ctx.Err())
	case <-c.shutdownCh:
		return ErrConnectionTerminated
	case <-c.commandLock:
		return nil
	}
}

func (c *Client) enqueueCommand(ctx context.Context, cmd string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("enqueue command: %w", err)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("enqueue command: %w", ctx.Err())
	case <-c.shutdownCh:
		return ErrConnectionTerminated
	case c.commandsCh <- cmd:
		return nil
	}
}

func (c *Client) waitForCommandResponse(
	ctx context.Context, commandName string, passthrough bool,
) (string, bool, error) {
	select {
	case resp, ok := <-c.commandResponseCh:
		if !ok {
			return "", false, ErrConnectionTerminated
		}

		response, err := validateCommandResponse(commandName, resp, passthrough)

		return response, false, err
	case <-ctx.Done():
		return "", true, fmt.Errorf("command error '%s': %w", commandName, ctx.Err())
	case <-c.shutdownCh:
		return "", false, ErrConnectionTerminated
	case <-c.commandTimer.C:
		return "", false, fmt.Errorf("command error '%s': %w", commandName, ErrTimeout)
	}
}

func validateCommandResponse(commandName, resp string, passthrough bool) (string, error) {
	if passthrough {
		return resp, nil
	}

	if resp == "" {
		return "", fmt.Errorf("command error '%s': %w", commandName, ErrEmptyResponse)
	}

	if strings.HasPrefix(resp, "ERROR:") {
		return resp, &ManagementCommandError{
			Command:  commandName,
			Response: strings.TrimSpace(resp),
		}
	}

	return resp, nil
}

// discardCommandResponse preserves command-response ordering after the caller
// stops waiting for a command that was already sent.
func (c *Client) discardCommandResponse() {
	defer func() {
		c.commandTimer.Stop()

		c.commandLock <- struct{}{}
	}()

	select {
	case <-c.commandResponseCh:
	case <-c.shutdownCh:
	case <-c.commandTimer.C:
	}
}

// SendCommandf formats a command using fmt.Sprintf and then calls SendCommand.
func (c *Client) SendCommandf(ctx context.Context, format string, a ...any) (string, error) {
	return c.SendCommand(ctx, fmt.Sprintf(format, a...), false)
}

// rawCommand writes a command followed by CRLF to the management interface.
func (c *Client) rawCommand(ctx context.Context, cmd, logCommand string) error {
	if c.logger.Enabled(ctx, slog.LevelDebug) {
		c.logger.LogAttrs(ctx, slog.LevelDebug, "send command", slog.String("command", logCommand))
	}

	c.commandsBuffer.Reset()
	c.commandsBuffer.WriteString(cmd)
	c.commandsBuffer.WriteString("\r\n")

	if err := c.conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return fmt.Errorf("unable to set read deadline: %w", err)
	}

	if _, err := c.commandsBuffer.WriteTo(c.conn); err != nil {
		return fmt.Errorf("unable to write into OpenVPN management connection: %w", err)
	}

	return nil
}

func managementCommandForError(cmd string, passthrough bool) string {
	if passthrough {
		return managementCommandName(cmd)
	}

	return strings.SplitN(cmd, "\r\n", 2)[0]
}

func managementCommandName(cmd string) string {
	cmdFirstLine, _, _ := strings.Cut(cmd, "\r\n")
	for field := range strings.FieldsSeq(cmdFirstLine) {
		return field
	}

	return ""
}

// readMessage .
func (c *Client) readMessage(buf *bytes.Buffer) error {
	buf.Reset()

	var line []byte

	for c.scanner.Scan() {
		line = c.scanner.Bytes()

		if len(line) == 0 {
			continue
		}

		if _, err := buf.Write(line); err != nil {
			return fmt.Errorf("unable to write string to buffer: %w", err)
		}

		if _, err := buf.WriteString("\r\n"); err != nil {
			return fmt.Errorf("unable to write newline to buffer: %w", err)
		}

		if c.isMessageLineEOF(line) {
			return nil
		}
	}

	if c.closed.Load() == 0 && c.scanner.Err() != nil {
		return fmt.Errorf("scanner error: %w", c.scanner.Err())
	}

	return io.EOF
}

func (c *Client) isMessageLineEOF(line []byte) bool {
	switch {
	// SUCCESS, ERROR, END, >HOLD, >INFO, >NOTIFY
	case bytes.HasPrefix(line, []byte("SU")),
		bytes.HasPrefix(line, []byte("ER")),
		bytes.HasPrefix(line, []byte("EN")),
		bytes.HasPrefix(line, []byte(">H")),
		bytes.HasPrefix(line, []byte(">I")),
		bytes.HasPrefix(line, []byte(">N")):
		return true
	default:
		return bytes.Equal(line, []byte(">CLIENT:ENV,END"))
	}
}
