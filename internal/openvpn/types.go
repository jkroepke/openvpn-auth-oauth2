package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
)

const (
	SchemeTCP  = "tcp"
	SchemeUnix = "unix"
)

type Client struct {
	conf    config.Config
	conn    net.Conn
	scanner *bufio.Scanner
	logger  *slog.Logger
	oauth2  oauth2Client

	connMu    sync.Mutex
	closed    atomic.Uint32
	commandMu sync.RWMutex

	commandsBuffer bytes.Buffer

	clientsCh         chan connection.Client
	commandResponseCh chan string
	commandsCh        chan string

	passThroughCh        chan string
	passThroughConnected atomic.Uint32
}

type oauth2Client interface {
	RefreshClientAuth(ctx context.Context, logger *slog.Logger, client connection.Client) (bool, error)
	ClientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client)
}
