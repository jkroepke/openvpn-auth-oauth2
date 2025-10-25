package plugin

import (
	"context"
	"log/slog"
	"sync"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
)

type pluginHandle struct {
	ctx              context.Context //nolint:containedctx
	logger           *slog.Logger
	managementClient *management.Server
	listenSocketAddr string
}

type clientContext struct {
	clientConfig string
	clientID     uint64
	authState    management.ClientAuth
	mu           sync.Mutex
}
