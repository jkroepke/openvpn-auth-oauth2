package main

import "github.com/jkroepke/openvpn-auth-oauth2/cmd"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.Execute(version, commit, date)
}
