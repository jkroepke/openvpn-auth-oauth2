//go:build linux

package main

import "C"
import (
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/http"
)

//nolint:gochecknoglobals
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type PluginHandle struct {
	logger *slog.Logger
	conf   config.Config
	server http.Server
}

func main() {
	// This function is here to satisfy Go's requirement of having a main function.
	// The main functionality is implemented in the openvpn_plugin_open_v3 function,
	// which will be called from C.
}
