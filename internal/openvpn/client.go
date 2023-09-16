package openvpn

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/encrypt"
	"go.uber.org/zap"
)

type Client struct {
	conf   *config.Config
	conn   net.Conn
	reader *bufio.Reader
	logger *zap.SugaredLogger

	clients         chan *ClientConnection
	commandResponse chan string
	commands        chan string
	errors          chan error
	shutdown        chan struct{}
}

func NewClient(logger *zap.SugaredLogger, conf *config.Config) *Client {
	return &Client{
		conf:   conf,
		logger: logger,

		errors:          make(chan error),
		clients:         make(chan *ClientConnection, 10),
		commandResponse: make(chan string, 10),
		commands:        make(chan string, 10),
		shutdown:        make(chan struct{}),
	}
}

func (c *Client) Connect() error {
	uri, err := url.Parse(c.conf.OpenVpn.Addr)
	if err != nil {
		return err
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

		if line, err := c.readMessage(); err != nil {
			return err
		} else if !strings.HasPrefix(line, "SUCCESS: password is correct") {
			return errors.New("wrong openvpn management interface password")
		}
	}

	c.logger.Info("Connection to OpenVPN management interfaced established.")

	go func() {
		for {
			message, err := c.readMessage()
			if err != nil {
				c.errors <- err
				return
			}
			if strings.HasPrefix(message, ">CLIENT:") {
				client, err := NewClientConnection(message)
				if err != nil {
					c.errors <- err
					return
				}

				c.clients <- client
			} else if strings.HasPrefix(message, ">HOLD:") {
				if err := c.rawCommand("hold release"); err != nil {
					c.errors <- err
					return
				}

				if line, err := c.readMessage(); err != nil {
					c.errors <- err
					return
				} else if !strings.HasPrefix(line, "SUCCESS:") {
					c.errors <- fmt.Errorf("invalid openvpn management interface response: %v", line)
					return
				}
			} else {
				c.commandResponse <- message
			}
		}
	}()

	go func() {
		for {
			if err := c.processClient(<-c.clients); err != nil {
				c.errors <- err
				return
			}
		}
	}()

	go func() {
		for {
			if err := c.rawCommand(<-c.commands); err != nil {
				c.errors <- err
				return
			}
		}
	}()

	for {
		select {
		case err := <-c.errors:
			_ = c.conn.Close()
			return err
		case <-c.shutdown:
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
		c.logger.Infow("new client connection",
			"cid", client.Cid,
			"kid", client.Kid,
			"reason", client.Reason,
			"common_name", client.Env["common_name"],
			"username", client.Env["username"],
		)

		if val, ok := client.Env["IV_SSO"]; !ok || !strings.Contains(val, "webauth") {
			c.logger.Warnw(ErrorSsoNotSupported,
				"cid", client.Cid,
				"kid", client.Kid,
				"reason", client.Reason,
				"common_name", client.Env["common_name"],
				"username", client.Env["username"],
			)

			c.SendCommand(`client-deny %d %d "%s" "%s"`, client.Cid, client.Kid, ErrorSsoNotSupported, ErrorSsoNotSupported)
			return nil
		}

		state, err := encrypt.Encrypt(fmt.Sprintf("%d|%d", client.Cid, client.Kid), c.conf.Http.SessionSecret)
		if err != nil {
			return err
		}

		c.logger.Info(state)

		sessionUrl := fmt.Sprintf("%s/oauth2/start?state=%s", c.conf.Http.BaseUrl, url.QueryEscape(state))
		c.logger.Infow("start pending auth",
			"cid", client.Cid,
			"kid", client.Kid,
			"reason", client.Reason,
			"common_name", client.Env["common_name"],
			"username", client.Env["username"],
		)
		c.SendCommand(`client-pending-auth %d %d "WEB_AUTH::%s" %d`, client.Cid, client.Kid, sessionUrl, 600)
		fallthrough

	case "ESTABLISHED":
		c.logger.Warnw("client established",
			"cid", client.Cid,
			"reason", client.Reason,
			"common_name", client.Env["common_name"],
			"username", client.Env["username"],
		)
	case "DISCONNECT":
		c.logger.Warnw("client disconnected",
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
	c.commands <- fmt.Sprintf(format, a...)
	return <-c.commandResponse
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
