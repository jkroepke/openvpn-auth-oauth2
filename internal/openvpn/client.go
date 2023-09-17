package openvpn

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

type Client struct {
	conf   *config.Config
	conn   net.Conn
	reader *bufio.Reader
	logger *slog.Logger

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

		errCh:             make(chan error),
		clientsCh:         make(chan *ClientConnection, 10),
		commandResponseCh: make(chan string, 10),
		commandsCh:        make(chan string, 10),
		shutdownCh:        make(chan struct{}),
	}
}

func (c *Client) Connect() error {
	uri, err := url.Parse(c.conf.OpenVpn.Addr)
	if err != nil {
		return fmt.Errorf("unable to parse openvpn addr as URI: %v", err)
	}

	c.conn, err = net.Dial(uri.Scheme, uri.Host)
	if err != nil {
		return err
	}
	defer c.conn.Close()

	c.reader = bufio.NewReader(c.conn)

	line, err := c.readMessage()
	if err != nil {
		return err
	}

	if strings.HasPrefix(line, "ENTER PASSWORD") {
		if err := c.rawCommand(c.conf.OpenVpn.Password); err != nil {
			return err
		}

		line, err := c.readMessage()
		if err != nil {
			return err
		}

		if !strings.HasPrefix(line, "SUCCESS: password is correct") {
			return errors.New("wrong openvpn management interface password")
		}
	}

	c.logger.Info("Connection to OpenVPN management interfaced established.")

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
			if err := c.processClient(<-c.clientsCh); err != nil {
				c.errCh <- err
				return
			}
		}
	}()

	go func() {
		for {
			if err := c.rawCommand(<-c.commandsCh); err != nil {
				c.errCh <- err
				return
			}
		}
	}()

	if resp := c.SendCommand("hold release"); !strings.HasPrefix(resp, "SUCCESS:") {
		return fmt.Errorf("invalid openvpn management interface response: %v", line)
	}

	if version := c.SendCommand("version"); version != "" {
		c.logger.Info(version)
	}

	for {
		select {
		case err := <-c.errCh:
			_ = c.conn.Close()
			return fmt.Errorf("OpenVPN management error: %v", err)
		case <-c.shutdownCh:
			_ = c.conn.Close()
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

		if slices.Contains(c.conf.OpenVpn.Bypass.CommonNames, client.Env["common_name"]) {
			c.logger.Info("client bypass authentication",
				"cid", client.Cid,
				"kid", client.Kid,
				"reason", client.Reason,
				"common_name", client.Env["common_name"],
				"username", client.Env["username"],
			)

			c.SendCommand(`client-auth-nt %d %d`, client.Cid, client.Kid)
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

			c.SendCommand(`client-deny %d %d "%s" "%s"`, client.Cid, client.Kid, ErrorSsoNotSupported, ErrorSsoNotSupported)
			return nil
		}

		session := state.New(client.Cid, client.Kid, client.Env["untrusted_ip"], client.Env["common_name"])
		if err := session.Encode(c.conf.Http.Secret); err != nil {
			return err
		}

		startUrl := fmt.Sprintf("%s/oauth2/start?state=%s", c.conf.Http.BaseUrl, url.QueryEscape(session.Encoded))
		c.logger.Info("start pending auth",
			"cid", client.Cid,
			"kid", client.Kid,
			"reason", client.Reason,
			"common_name", client.Env["common_name"],
			"username", client.Env["username"],
		)
		c.SendCommand(`client-pending-auth %d %d "WEB_AUTH::%s" %d`, client.Cid, client.Kid, startUrl, 600)
	case "ESTABLISHED":
		c.logger.Warn("client established",
			"cid", client.Cid,
			"reason", client.Reason,
			"common_name", client.Env["common_name"],
			"username", client.Env["username"],
		)
	case "DISCONNECT":
		c.logger.Warn("client disconnected",
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

// SendCommand passes command to a given connection (adds logging and EOL character) and returns the response
func (c *Client) SendCommand(format string, a ...any) string {
	c.commandsCh <- fmt.Sprintf(format, a...)
	return <-c.commandResponseCh
}

// rawCommand passes command to a given connection (adds logging and EOL character)
func (c *Client) rawCommand(cmd string) error {
	c.logger.Debug(cmd)

	if _, err := fmt.Fprint(c.conn, cmd+"\n"); err != nil {
		return err
	}
	return nil
}

// readMessage .
func (c *Client) readMessage() (string, error) {
	result := ""
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		result += line
		if strings.HasPrefix(line, ">CLIENT:ENV,END") ||
			strings.Index(line, "END") == 0 ||
			strings.Index(line, "SUCCESS:") == 0 ||
			strings.Index(line, "ERROR:") == 0 ||
			strings.HasPrefix(line, ">HOLD:") ||
			strings.HasPrefix(line, ">INFO:") {

			c.logger.Debug(result)
			return result, nil
		}
	}
}
