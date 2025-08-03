package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/jkroepke/openvpn-auth-oauth2/cmd/daemon"
	"github.com/jkroepke/openvpn-auth-oauth2/cmd/state"
)

func main() {
	if len(os.Args) == 1 {
		os.Args = append(os.Args, "")
	}

	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGUSR1)

	switch os.Args[1] {
	case "state":
		os.Exit(state.Execute(os.Args, os.Stdout)) //nolint:forbidigo // entry point
	default:
		os.Exit(daemon.Execute(os.Args, os.Stdout, termCh)) //nolint:forbidigo // entry point
	}
}
