package main

import (
	"os"

	"github.com/jkroepke/openvpn-auth-oauth2/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(cmd.Execute(version, commit, date))
}
