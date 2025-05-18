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
	oauth2               oauth2Client
	conn                 net.Conn
	commandsCh           chan string
	logger               *slog.Logger
	scanner              *bufio.Scanner
	commandResponseCh    chan string
	clientsCh            chan connection.Client
	passThroughCh        chan string
	commandsBuffer       bytes.Buffer
	conf                 config.Config
	commandMu            sync.RWMutex
	connMu               sync.Mutex
	closed               atomic.Uint32
	passThroughConnected atomic.Uint32
}

type oauth2Client interface {
	RefreshClientAuth(ctx context.Context, logger *slog.Logger, client connection.Client) (bool, error)
	ClientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client)
}
