// Explicitly disable httpmuxgo121, because Debian build system disables it.
// ref: https://github.com/jkroepke/openvpn-auth-oauth2/issues/680#issuecomment-3686988447
//
//go:debug httpmuxgo121=0
package main

import (
	"github.com/jkroepke/openvpn-auth-oauth2/cmd"
)

func main() {
	cmd.Execute()
}
