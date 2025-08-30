//go:build linux

package main

import "C"

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-plugin/cache"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-plugin/management"
)

type pluginHandle struct {
	ctx              context.Context
	cancel           context.CancelFunc
	logger           *slog.Logger
	managementClient *management.Server
	cache            *cache.Cache
}

func main() {
	// This function is here to satisfy Go's requirement of having a main function.
	// The main functionality is implemented in the openvpn_plugin_open_v3 function,
	// which will be called from C.
}
