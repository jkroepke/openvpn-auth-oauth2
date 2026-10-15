package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/metrics"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

const (
	SchemeTCP  = "tcp"
	SchemeUnix = "unix"
)

type Client struct {
	oauth2            oauth2Client
	conn              net.Conn
	commandResponseCh chan string
	commandLock       chan struct{}
	commandTimer      *time.Timer
	commandsCh        chan string
	logger            *slog.Logger
	scanner           *bufio.Scanner
	ctxCancel         context.CancelFunc
	clientsCh         chan connection.Client
	passThroughCh     chan string
	shutdownCh        chan struct{}
	conf              *config.Config
	metrics           *metrics.Metrics
	// pendingClientAddress is owned by the handleMessages goroutine.
	pendingClientAddress clientAddress
	commandsBuffer       bytes.Buffer
	acceptMu             sync.Mutex
	connMu               sync.Mutex
	closed               atomic.Uint32
	commandTimedOut      atomic.Bool
	ready                atomic.Bool
	passThroughConnected atomic.Uint32
}

// clientAddress is the primary VPN address announced by >CLIENT:ADDRESS.
type clientAddress struct {
	addr string
	cid  uint64
}

type oauth2Client interface {
	RefreshClientAuth(ctx context.Context, logger *slog.Logger, client connection.Client) (types.RefreshResult, bool, error)
	RegisterClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, username string, identity sessionregistry.Identity)
	ResolveClientConfigNames(
		authMode types.AuthMode,
		session state.State,
		tokens *idtoken.IDToken,
		user types.UserInfo,
	) ([]string, error)
	ClientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client)
	EncryptState(oidcState state.State) (state.EncryptedState, error)
}
