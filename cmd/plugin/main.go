//go:build linux

package main

import "C"

import (
	"context"
	"log/slog"
)

//nolint:gochecknoglobals
//goland:noinspection GoUnusedGlobalVariable
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type PluginHandle struct {
	ctx              context.Context
	cancel           context.CancelFunc
	logger           *slog.Logger
	managementClient *ManagementClient
}

func main() {
	// This function is here to satisfy Go's requirement of having a main function.
	// The main functionality is implemented in the openvpn_plugin_open_v3 function,
	// which will be called from C.
}
