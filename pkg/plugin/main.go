//go:build linux

package main

import "C"

import (
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
)

//nolint:gochecknoglobals
//goland:noinspection GoUnusedGlobalVariable
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type PluginHandle struct {
	logger *slog.Logger
	conf   *config.Config
	server *httpserver.Server
}

func main() {
	// This function is here to satisfy Go's requirement of having a main function.
	// The main functionality is implemented in the openvpn_plugin_open_v3 function,
	// which will be called from C.
}
