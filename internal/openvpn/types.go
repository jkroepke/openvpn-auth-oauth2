package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

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
	commandsCh           chan string
	logger               *slog.Logger
	scanner              *bufio.Scanner
	ctxCancel            context.CancelFunc
	clientsCh            chan connection.Client
	passThroughCh        chan string
	conf                 *config.Config
	commandsBuffer       bytes.Buffer
	commandMu            sync.Mutex
	connMu               sync.Mutex
	closed               atomic.Uint32
	passThroughConnected atomic.Uint32
}

type oauth2Client interface {
	RefreshClientAuth(ctx context.Context, logger *slog.Logger, client connection.Client) (types.UserInfo, *idtoken.IDToken, []string, bool, error)
	ResolveClientConfigNames(tokens *idtoken.IDToken, openVPNUserCommonName, username string) ([]string, error)
	ClientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client)
	KillDuplicateUsernameSession(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, clientID, username string) error
	StoreDuplicateUsernameSession(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, clientID, username string)
	EncryptState(oidcState state.State) (state.EncryptedState, error)
}

func currentClientID(conf *config.Config, client connection.Client) string {
	if conf.OAuth2.Refresh.UseSessionID && client.SessionID != "" {
		return client.SessionID
	}

	return strconv.FormatUint(client.CID, 10)
}

func stateClientIdentifier(client connection.Client) state.ClientIdentifier {
	return state.ClientIdentifier{
		CID:               client.CID,
		KID:               client.KID,
		CommonName:        client.CommonName,
		SessionID:         client.SessionID,
		UsernameIsDefined: client.UsernameIsDefined,
	}
}
