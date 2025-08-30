//go:build linux

package main

import "C"

import (
	"fmt"
	"os"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-plugin/client"
)

func (p *pluginHandle) writeToAuthFile(client client.Client, auth string) error {
	if err := os.WriteFile(client.AuthControlFile, []byte(auth), 0o600); err != nil {
		return fmt.Errorf("write to file %s: %w", client.AuthFailedReasonFile, err)
	}

	return nil
}
