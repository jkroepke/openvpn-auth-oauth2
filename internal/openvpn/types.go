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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
)

const (
	SchemeTCP  = "tcp"
	SchemeUnix = "unix"
)

type Client struct {
	conf    *config.Config
	conn    net.Conn
	scanner *bufio.Scanner
	logger  *slog.Logger
	oauth2  *oauth2.Provider

	connMu sync.Mutex
	closed atomic.Uint32

	ctx       context.Context //nolint:containedctx
	ctxCancel context.CancelCauseFunc

	commandsBuffer bytes.Buffer

	clientsCh         chan connection.Client
	commandResponseCh chan string
	commandsCh        chan string
	passthroughCh     chan string

	passthroughConnected atomic.Uint32
}
