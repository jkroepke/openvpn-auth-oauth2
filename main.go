package main

import (
	"os"

	"github.com/jkroepke/openvpn-auth-oauth2/cmd/daemon"
	"github.com/jkroepke/openvpn-auth-oauth2/cmd/state"
)

//nolint:gochecknoglobals
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) == 1 {
		os.Args = append(os.Args, "")
	}

	switch os.Args[1] {
	case "state":
		os.Exit(state.Execute(os.Args, os.Stdout, version, commit, date))
	default:
		os.Exit(daemon.Execute(os.Args, os.Stdout, version, commit, date))
	}
}
