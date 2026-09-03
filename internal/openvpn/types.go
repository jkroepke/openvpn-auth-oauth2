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
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

const (
	SchemeTCP  = "tcp"
	SchemeUnix = "unix"
)

type Client struct {
	oauth2               oauth2Client
	conn                 net.Conn
	commandResponseCh    chan string
	commandLock          chan struct{}
	commandTimer         *time.Timer
	commandsCh           chan string
	logger               *slog.Logger
	scanner              *bufio.Scanner
	ctxCancel            context.CancelFunc
	clientsCh            chan connection.Client
	passThroughCh        chan string
	shutdownCh           chan struct{}
	conf                 *config.Config
	commandsBuffer       bytes.Buffer
	acceptMu             sync.Mutex
	connMu               sync.Mutex
	closed               atomic.Uint32
	passThroughConnected atomic.Uint32
}

type oauth2Client interface {
	RefreshClientAuth(ctx context.Context, logger *slog.Logger, client connection.Client) (types.UserInfo, *idtoken.IDToken, []string, bool, error)
	ResolveClientConfigNames(
		authMode types.AuthMode,
		session state.State,
		tokens *idtoken.IDToken,
		user types.UserInfo,
	) ([]string, error)
	ClientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client)
	EncryptState(oidcState state.State) (state.EncryptedState, error)
}
