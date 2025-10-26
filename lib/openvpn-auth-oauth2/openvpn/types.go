package openvpn

import (
	"context"
	"log/slog"
	"sync"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
)

type PluginHandle struct {
	ctx              context.Context //nolint:containedctx
	logger           *slog.Logger
	managementClient *management.Server
	listenSocketAddr string
}

type ClientContext struct {
	clientConfig string
	clientID     uint64
	mu           sync.Mutex
}
