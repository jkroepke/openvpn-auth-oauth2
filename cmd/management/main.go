package main

import (
	"fmt"
	"os"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/lib/management"
)

var version = "unknown"

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		os.Exit(0)
	}

	management.Run()
}
