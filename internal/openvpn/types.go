package openvpn

import (
	"bufio"
	"bytes"
	"context"
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

	connMu sync.Mutex
	closed bool

	ctx       context.Context //nolint:containedctx
	ctxCancel context.CancelCauseFunc

	commandsBuffer bytes.Buffer

	clientsCh         chan connection.Client
	commandResponseCh chan string
	commandsCh        chan string
}
