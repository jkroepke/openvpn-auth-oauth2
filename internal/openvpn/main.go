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

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

const minManagementInterfaceVersion = 5

func New(logger *slog.Logger, conf config.Config) *Client {
	client := &Client{
		conf:   conf,
		logger: logger,

		connMu:    sync.Mutex{},
		commandMu: sync.RWMutex{},

		commandsBuffer: bytes.Buffer{},

		clientsCh:         make(chan connection.Client, 10),
		commandResponseCh: make(chan string),
		commandsCh:        make(chan string, 10),
		passThroughCh:     make(chan string, 10),
	}

	client.commandsBuffer.Grow(512)

	return client
}

func (c *Client) SetOAuth2Client(client oauth2Client) {
	c.oauth2 = client
}

//nolint:cyclop
func (c *Client) Connect(ctx context.Context) error {
	var err error

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	c.logger.LogAttrs(ctx, slog.LevelInfo, "connect to openvpn management interface "+c.conf.OpenVPN.Addr.String())

	if err = c.setupConnection(); err != nil {
		return fmt.Errorf("unable to connect to openvpn management interface %s: %w", c.conf.OpenVPN.Addr.String(), err)
	}

	c.scanner = bufio.NewScanner(c.conn)
	c.scanner.Split(bufio.ScanLines)
	c.scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), bufio.MaxScanTokenSize)

	if err = c.handlePassword(ctx); err != nil {
		_ = c.conn.Close()

		return fmt.Errorf("unable to authenticate with OpenVPN management interface: %w", err)
	}

	defer c.Shutdown()

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

	if err := c.checkManagementInterfaceVersion(); err != nil {
		if errors.Is(err, ErrConnectionTerminated) {
			return nil
		}

		return fmt.Errorf("unable to check OpenVPN management interface version: %w", err)
	}

	select {
	case <-ctx.Done():
		c.Shutdown()
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

func (c *Client) setupConnection() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	var err error

	switch c.conf.OpenVPN.Addr.Scheme {
	case SchemeTCP:
		c.conn, err = net.DialTimeout(c.conf.OpenVPN.Addr.Scheme, c.conf.OpenVPN.Addr.Host, 1*time.Second)
	case SchemeUnix:
		c.conn, err = net.DialTimeout(c.conf.OpenVPN.Addr.Scheme, c.conf.OpenVPN.Addr.Path, 1*time.Second)
	default:
		err = fmt.Errorf("unable to connect to openvpn management interface: %w %s", ErrUnknownProtocol, c.conf.OpenVPN.Addr.Scheme)
	}

	return err
}

func (c *Client) checkManagementInterfaceVersion() error {
	resp, err := c.SendCommand("version", false)
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

	c.logger.Info(utils.StringConcat(versionParts[0], " - ", versionParts[1]))

	managementInterfaceVersion, err := strconv.Atoi(versionParts[1][len(versionParts[1])-1:])
	if err != nil {
		return fmt.Errorf("unable to parse openvpn management interface version: %w", err)
	}

	// Management Interface Version 5 is required at minimum
	// ref: https://github.com/OpenVPN/openvpn/commit/a261e173341f8e68505a6ab5a413d09b0797a459
	if managementInterfaceVersion < minManagementInterfaceVersion {
		return ErrRequireManagementInterfaceVersion5
	}

	return nil
}

func (c *Client) checkClientSsoCapabilities(client connection.Client) bool {
	return strings.Contains(client.IvSSO, "webauth")
}

// Shutdown shutdowns the client connection.
func (c *Client) Shutdown() {
	c.commandMu.Lock()
	defer c.commandMu.Unlock()

	if !c.closed.CompareAndSwap(0, 1) {
		return
	}

	c.logger.Info("shutdown OpenVPN management connection")

	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn != nil {
		_ = c.conn.Close()

		c.conn = nil
	}

	close(c.commandsCh)
}

// SendCommand passes command to a given connection (adds logging and EOL character) and returns the response.
func (c *Client) SendCommand(cmd string, passthrough bool) (string, error) {
	c.commandMu.RLock()
	defer c.commandMu.RUnlock()

	if cmd == "\x00" || c.closed.Load() == 1 {
		return "", nil
	}

	c.commandsCh <- cmd

	select {
	case resp, ok := <-c.commandResponseCh:
		if !ok {
			return "", ErrConnectionTerminated
		}

		if passthrough {
			return resp, nil
		}

		if resp == "" {
			cmdFirstLine := strings.SplitN(cmd, "\r\n", 2)[0]

			return "", fmt.Errorf("command error '%s': %w", cmdFirstLine, ErrEmptyResponse)
		}

		if strings.HasPrefix(resp, "ERROR:") {
			cmdFirstLine := strings.SplitN(cmd, "\r\n", 2)[0]
			c.logger.Warn(fmt.Sprintf("command error '%s': %s", cmdFirstLine, resp))
		}

		return resp, nil
	case <-time.After(c.conf.OpenVPN.CommandTimeout):
		cmdFirstLine := strings.SplitN(cmd, "\r\n", 2)[0]

		return "", fmt.Errorf("command error '%s': %w", cmdFirstLine, ErrTimeout)
	}
}

// SendCommandf passes command to a given connection (adds logging and EOL character) and returns the response.
func (c *Client) SendCommandf(format string, a ...any) (string, error) {
	return c.SendCommand(fmt.Sprintf(format, a...), false)
}

// rawCommand passes command to a given connection (adds logging and EOL character).
func (c *Client) rawCommand(ctx context.Context, cmd string) error {
	if c.logger.Enabled(ctx, slog.LevelDebug) {
		c.logger.LogAttrs(ctx, slog.LevelDebug, "send command", slog.String("command", cmd))
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
	switch string(line[0:2]) {
	// SUCCESS, ERROR, END, >HOLD, >INFO, >NOTIFY
	case "SU", "ER", "EN", ">H", ">I", ">N":
		return true
	default:
		return bytes.Equal(line, []byte(">CLIENT:ENV,END"))
	}
}
