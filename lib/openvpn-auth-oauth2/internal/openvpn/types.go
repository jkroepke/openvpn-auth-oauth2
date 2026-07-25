//go:build (darwin || linux || openbsd || freebsd) && cgo

package openvpn

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/internal/management"
)

type managementServer interface {
	Listen(ctx context.Context, addr string) error
	Close()
	ClientAuth(ctx context.Context, clientID uint64, message string) (*management.Response, error)
	ClientDisconnect(message string) error
	RegisterPendingPoller(clientID uint64) (chan *management.Response, error)
	WaitPendingPoller(
		ctx context.Context,
		clientID uint64,
		timeout time.Duration,
		respCh <-chan *management.Response,
	) (*management.Response, error)
	CancelPendingPoller(clientID uint64)
}

type PluginHandle struct {
	ctx              context.Context //nolint:containedctx
	cancel           context.CancelFunc
	logger           *slog.Logger
	managementClient managementServer
	listenSocketAddr string
}

type ClientContext struct {
	clientConfig string
	clientID     uint64
	mu           sync.Mutex
}
