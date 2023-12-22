package openvpn

import (
	"bufio"
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

	mu     sync.Mutex
	closed bool

	clientsCh         chan connection.Client
	commandResponseCh chan string
	commandsCh        chan string
	errCh             chan error
	shutdownCh        chan struct{}
}
