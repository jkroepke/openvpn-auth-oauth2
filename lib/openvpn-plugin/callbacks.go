//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-plugin/client"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-plugin/management"
)

func (p *pluginHandle) writeToAuthFile(openvpnClient *client.Client, auth string) error {
	if openvpnClient.AuthControlFile == "" {
		return errors.New("auth_control_file not set")
	}

	if err := os.WriteFile(openvpnClient.AuthControlFile, []byte(auth), 0o600); err != nil {
		return fmt.Errorf("write to file %s: %w", openvpnClient.AuthControlFile, err)
	}

	return nil
}

// writeAuthFailed writes the auth_pending_file can be written, which causes the openvpn
// server to send a pending auth request to the client. See doc/management.txt
// for more details on this authentication mechanism. The format of the
// auth_pending_file is
// line 1: timeout in seconds
// line 2: Pending auth method the client needs to support (e.g. webauth)
// line 3: EXTRA (e.g. WEB_AUTH::http://www.example.com)
func (p *pluginHandle) writeAuthPending(openvpnClient *client.Client, resp *management.Response) error {
	if openvpnClient.AuthPendingFile != "" {
		pendingData := fmt.Sprintf("%s\nwebauth\n%s\n", resp.Timeout, resp.Message)
		if err := os.WriteFile(openvpnClient.AuthPendingFile, []byte(pendingData), 0o600); err != nil {
			return fmt.Errorf("write to pending file %s: %w", openvpnClient.AuthPendingFile, err)
		}
	}

	// Also write "2" to the auth control file to indicate deferred auth
	if openvpnClient.AuthControlFile != "" {
		if err := os.WriteFile(openvpnClient.AuthControlFile, []byte("2"), 0o600); err != nil {
			return fmt.Errorf("write to control file %s: %w", openvpnClient.AuthControlFile, err)
		}
	}

	return nil
}
