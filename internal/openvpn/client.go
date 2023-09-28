package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

type Client struct {
	conf   *config.Config
	conn   net.Conn
	reader *bufio.Reader
	logger *slog.Logger

	closed bool

	clientsCh         chan *ClientConnection
	commandResponseCh chan string
	commandsCh        chan string
	errCh             chan error
	shutdownCh        chan struct{}
}

func NewClient(logger *slog.Logger, conf *config.Config) *Client {
	return &Client{
		conf:   conf,
		logger: logger,

		closed: false,

		errCh:             make(chan error, 1),
		clientsCh:         make(chan *ClientConnection, 10),
		commandResponseCh: make(chan string, 10),
		commandsCh:        make(chan string, 10),
		shutdownCh:        make(chan struct{}, 1),
	}
}

func (c *Client) Connect() error {
	var err error
	c.logger.Info(utils.StringConcat("connect to openvpn management interface ", c.conf.OpenVpn.Addr.String()))
	switch c.conf.OpenVpn.Addr.Scheme {
	case "tcp":
		c.conn, err = net.Dial(c.conf.OpenVpn.Addr.Scheme, c.conf.OpenVpn.Addr.Host)
	case "unix":
		c.conn, err = net.Dial(c.conf.OpenVpn.Addr.Scheme, c.conf.OpenVpn.Addr.Path)
	default:
		return errors.New(utils.StringConcat("unable to connect to openvpn management interface: unknown protocol ", c.conf.OpenVpn.Addr.Scheme))
	}

	if err != nil {
		return errors.New(utils.StringConcat("unable to connect to openvpn management interface ", c.conf.OpenVpn.Addr.String(), ": ", err.Error()))
	}
	defer c.conn.Close()
	c.reader = bufio.NewReader(c.conn)

	if c.conf.OpenVpn.Password != "" {
		if err := c.rawCommand(utils.StringConcat(c.conf.OpenVpn.Password, "\n")); err != nil {
			return err
		}

		line, err := c.readMessage()
		if err != nil {
			return err
		}

		if !strings.Contains(line, "SUCCESS: password is correct") {
			return errors.New("wrong openvpn management interface password")
		}
	}

	go func() {
		for {
			message, err := c.readMessage()
			if err != nil {
				c.errCh <- err
				return
			}

			if strings.HasPrefix(message, ">CLIENT:") {
				client, err := NewClientConnection(message)
				if err != nil {
					c.errCh <- err
					return
				}

				c.clientsCh <- client
			} else if strings.HasPrefix(message, "SUCCESS:") || strings.HasPrefix(message, "ERROR:") || strings.HasPrefix(message, "OpenVPN Version:") {
				if strings.HasPrefix(message, "ERROR:") {
					c.logger.Warn(fmt.Sprintf("Error from OpenVPN: %s", message))
				}
				c.commandResponseCh <- message
			}
		}
	}()

	go func() {
		for {
			client := <-c.clientsCh
			if client == nil {
				return
			}

			if err := c.processClient(client); err != nil {
				c.errCh <- err
				return
			}
		}
	}()

	go func() {
		for {
			command := <-c.commandsCh
			if command == "" {
				return
			}

			if err := c.rawCommand(command); err != nil {
				c.errCh <- err
				return
			}
		}
	}()

	respCh := make(chan string, 1)
	go func() {
		respCh <- c.SendCommand("hold release")
	}()
	select {
	case resp := <-respCh:
		if !strings.HasPrefix(resp, "SUCCESS:") {
			return errors.New(utils.StringConcat("invalid openvpn management interface response: ", resp))
		}
	case <-time.After(10 * time.Second):
		return errors.New("timeout while waiting from openvpn management interface response")
	}

	c.logger.Info("Connection to OpenVPN management interfaced established.")

	if version := c.SendCommand("version"); version != "" {
		c.logger.Info(version)
	}

	for {
		select {
		case err := <-c.errCh:
			c.close()
			if err != nil {
				return errors.New(utils.StringConcat("OpenVPN management error: ", err.Error()))
			}
			return nil
		case <-c.shutdownCh:
			c.close()
			return nil
		}
	}
}

func (c *Client) processClient(client *ClientConnection) error {
	switch client.Reason {
	case "CONNECT":
		fallthrough
	case "REAUTH":
		c.logger.Info("new client connection",
			"cid", client.Cid,
			"kid", client.Kid,
			"reason", client.Reason,
			"common_name", client.Env["common_name"],
			"username", client.Env["username"],
		)

		if val, ok := client.Env["common_name"]; ok && slices.Contains(c.conf.OpenVpn.Bypass.CommonNames, val) {
			c.logger.Info("client bypass authentication",
				"cid", client.Cid,
				"kid", client.Kid,
				"reason", client.Reason,
				"common_name", client.Env["common_name"],
				"username", client.Env["username"],
			)

			if c.conf.OpenVpn.AuthTokenUser {
				c.SendCommandf("client-auth %d %d\npush \"auth-token-user %s\"\nEND", client.Cid, client.Kid, base64.StdEncoding.EncodeToString([]byte(client.Env["common_name"])))
			} else {
				c.SendCommandf("client-auth-nt %d %d", client.Cid, client.Kid)
			}

			return nil
		}

		if val, ok := client.Env["IV_SSO"]; !ok || !strings.Contains(val, "webauth") {
			c.logger.Warn(ErrorSsoNotSupported,
				"cid", client.Cid,
				"kid", client.Kid,
				"reason", client.Reason,
				"common_name", client.Env["common_name"],
				"username", client.Env["username"],
			)

			c.SendCommandf(`client-deny %d %d "%s" "%s"`, client.Cid, client.Kid, ErrorSsoNotSupported, ErrorSsoNotSupported)
			return nil
		}

		session := state.New(client.Cid, client.Kid, client.Env["untrusted_ip"], client.Env["common_name"])
		if err := session.Encode(c.conf.Http.Secret); err != nil {
			return errors.New(utils.StringConcat("error encoding state: ", err.Error()))
		}

		startUrl := utils.StringConcat(strings.TrimSuffix(c.conf.Http.BaseUrl.String(), "/"), "/oauth2/start?state=", url.QueryEscape(session.Encoded))
		c.logger.Info("start pending auth",
			"cid", client.Cid,
			"kid", client.Kid,
			"reason", client.Reason,
			"common_name", client.Env["common_name"],
			"username", client.Env["username"],
		)
		c.SendCommandf(`client-pending-auth %d %d "WEB_AUTH::%s" %d`, client.Cid, client.Kid, startUrl, 600)
	case "ESTABLISHED":
		c.logger.Info("client established",
			"cid", client.Cid,
			"reason", client.Reason,
			"common_name", client.Env["common_name"],
			"username", client.Env["username"],
		)
	case "DISCONNECT":
		c.logger.Info("client disconnected",
			"cid", client.Cid,
			"reason", client.Reason,
			"common_name", client.Env["common_name"],
			"username", client.Env["username"],
		)
	default:
		return fmt.Errorf("unknown client reason: %s", client.Reason)
	}
	return nil
}

// Shutdown shutdowns the client connection
func (c *Client) Shutdown() {
	if !c.closed {
		c.logger.Info("shutdown connection")
		c.shutdownCh <- struct{}{}
	}
}

// SendCommand passes command to a given connection (adds logging and EOL character) and returns the response
func (c *Client) SendCommand(cmd string) string {
	c.commandsCh <- utils.StringConcat(cmd, "\n")
	return <-c.commandResponseCh
}

// SendCommandf passes command to a given connection (adds logging and EOL character) and returns the response
func (c *Client) SendCommandf(format string, a ...any) string {
	return c.SendCommand(fmt.Sprintf(format, a...))
}

// rawCommand passes command to a given connection (adds logging and EOL character)
func (c *Client) rawCommand(cmd string) error {
	if c.logger.Enabled(context.Background(), slog.LevelDebug) {
		c.logger.Debug(cmd)
	}
	_, err := c.conn.Write([]byte(cmd))
	return err
}

// readMessage .
func (c *Client) readMessage() (string, error) {
	var buf bytes.Buffer
	for {
		line, err := c.reader.ReadBytes('\n')
		if err != nil {
			return "", err
		}

		if _, err := buf.Write(line); err != nil {
			return "", err
		}

		if bytes.HasPrefix(line, []byte(">CLIENT:ENV,END")) ||
			bytes.Index(line, []byte("END")) == 0 ||
			bytes.Index(line, []byte("SUCCESS:")) == 0 ||
			bytes.Index(line, []byte("ERROR:")) == 0 ||
			bytes.HasPrefix(line, []byte(">HOLD:")) ||
			bytes.HasPrefix(line, []byte(">INFO:")) ||
			bytes.HasPrefix(line, []byte(">NOTIFY:")) ||
			bytes.HasPrefix(line, []byte("ENTER PASSWORD:")) {
			if c.logger.Enabled(context.Background(), slog.LevelDebug) {
				c.logger.Debug(buf.String())
			}
			return buf.String(), nil
		}
	}
}

func (c *Client) close() {
	c.closed = true
	_ = c.conn.Close()
	close(c.errCh)
	close(c.shutdownCh)
	close(c.clientsCh)
	close(c.commandsCh)
	close(c.commandResponseCh)
}
