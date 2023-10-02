package openvpn

import (
	"bufio"
	"log/slog"
	"net"
	"sync"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

type Client struct {
	conf    config.Config
	conn    net.Conn
	scanner *bufio.Scanner
	logger  *slog.Logger

	mu     sync.Mutex
	closed bool

	clientsCh         chan ClientConnection
	commandResponseCh chan string
	commandsCh        chan string
	errCh             chan error
	shutdownCh        chan struct{}
}
