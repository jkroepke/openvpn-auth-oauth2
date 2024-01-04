package openvpn

import (
	"bufio"
	"bytes"
	"log/slog"
	"net"
	"sync"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
)

type Client struct {
	conf    config.Config
	conn    net.Conn
	scanner *bufio.Scanner
	logger  *slog.Logger
	oauth2  *oauth2.Provider

	shutdownMu sync.Mutex
	connMu     sync.Mutex
	closed     bool

	commandsBuffer bytes.Buffer

	clientsCh         chan connection.Client
	commandResponseCh chan string
	commandsCh        chan string
	errCh             chan error
}
