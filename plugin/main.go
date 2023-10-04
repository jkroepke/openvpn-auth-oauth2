package main

import "C"
import (
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
)

//nolint:gochecknoglobals
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type PluginHandle struct {
	logger   *slog.Logger
	conf     config.Config
	provider oauth2.Provider
}

func main() {
	// This function is here to satisfy Go's requirement of having a main function.
	// The main functionality is implemented in the openvpn_plugin_open_v3 function,
	// which will be called from C.
}
