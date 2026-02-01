//go:build linux && cgo

package openvpn

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/client"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util"
)

// handlePluginUp handles the OPENVPN_PLUGIN_UP event, which is triggered after
// OpenVPN has completed its initialization and the daemon is ready.
// This function starts the management interface listener.
//
// Returns:
//   - c.OpenVPNPluginFuncSuccess if the listener starts successfully
//   - c.OpenVPNPluginFuncError if the listener fails to start
func (p *PluginHandle) handlePluginUp() c.OpenVPNPluginFuncStatus {
	if err := p.managementClient.Listen(p.ctx, p.listenSocketAddr); err != nil {
		p.logger.ErrorContext(p.ctx, "failed to start management client",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	p.logger.InfoContext(p.ctx, "listener started",
		slog.Any("addr", p.listenSocketAddr),
	)

	return c.OpenVPNPluginFuncSuccess
}

// handleAuthUserPassVerify handles the OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY event,
// which is triggered when a client attempts to authenticate.
//
// This function:
//  1. Parses client environment variables from OpenVPN
//  2. Creates a client context with session information
//  3. Sends authentication request to the management interface
//  4. Handles the authentication response (accept, deny, or pending)
//  5. For pending auth, starts a background poller to wait for completion
//
// Parameters:
//   - clientEnvList: Unsafe pointer to OpenVPN environment variables
//   - perClientContext: Per-client context for storing authentication state
//
// Returns:
//   - c.OpenVPNPluginFuncSuccess if authentication succeeds immediately
//   - c.OpenVPNPluginFuncError if authentication fails or an error occurs
//   - C.OPENVPN_PLUGIN_FUNC_DEFERRED if authentication is pending (OAuth2 flow in progress)
//
//nolint:cyclop,gocognit
func (p *PluginHandle) handleAuthUserPassVerify(clientEnvList **c.Char, perClientContext *ClientContext) c.OpenVPNPluginFuncStatus {
	envArray, err := util.NewEnvList(clientEnvList)
	if err != nil {
		p.logger.ErrorContext(p.ctx, "parse env vars",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	sessionID, ok := envArray["session_id"]
	if !ok {
		p.logger.ErrorContext(p.ctx, "missing session_id in env vars")

		return c.OpenVPNPluginFuncError
	}

	currentClientID := atomic.AddUint64(&clientIDCounter, 1)

	logger := p.logger.With(
		slog.Uint64("client_id", currentClientID),
		slog.String("session_id", sessionID),
		slog.String("client_ip", fmt.Sprintf("%s:%s", envArray["untrusted_ip"], envArray["untrusted_port"])),
	)

	logger.DebugContext(p.ctx, "env", slog.Any("env", envArray))

	openVPNClient, err := client.NewClient(currentClientID, envArray)
	if err != nil {
		logger.ErrorContext(p.ctx, "create OpenVPN client from env vars",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	resp, err := p.managementClient.ClientAuth(currentClientID, openVPNClient.GetConnectMessage())
	if err != nil {
		logger.ErrorContext(p.ctx, "send client to management interface",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	perClientContext.mu.Lock()
	perClientContext.clientID = currentClientID
	perClientContext.mu.Unlock()

	logger.InfoContext(p.ctx, "client auth response: "+resp.ClientAuth.String())

	switch resp.ClientAuth {
	case management.ClientAuthAccept:
		if err := openVPNClient.WriteToAuthFile("1"); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)

			return c.OpenVPNPluginFuncError
		}

		logger.InfoContext(p.ctx, "authentication accepted")

		perClientContext.mu.Lock()
		perClientContext.clientConfig = resp.ClientConfig
		perClientContext.mu.Unlock()

		return c.OpenVPNPluginFuncSuccess
	case management.ClientAuthDeny:
		reason := "authentication failed"
		if resp.Message != "" {
			reason = resp.Message
		}

		logger.InfoContext(p.ctx, "authentication denied",
			slog.String("reason", reason),
		)

		if err := openVPNClient.WriteToAuthFile("0"); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)

			return c.OpenVPNPluginFuncError
		}

		return c.OpenVPNPluginFuncSuccess
	case management.ClientAuthPending:
		// Write "2" to auth control file to indicate deferred auth
		if err := openVPNClient.WriteAuthPending(resp); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)

			return c.OpenVPNPluginFuncError
		}

		logger.InfoContext(p.ctx, "authentication pending")

		go func() {
			resp, err := p.managementClient.AuthPendingPoller(currentClientID, 5*time.Minute)
			if err != nil {
				logger.ErrorContext(p.ctx, "poll deferred auth state",
					slog.Any("err", err),
				)

				return
			}

			switch resp.ClientAuth {
			case management.ClientAuthAccept:
				if err := openVPNClient.WriteToAuthFile("1"); err != nil {
					logger.ErrorContext(p.ctx, "write to auth file",
						slog.Any("err", err),
					)

					return
				}

				logger.InfoContext(p.ctx, "authentication accepted")

				perClientContext.mu.Lock()
				perClientContext.clientConfig = resp.ClientConfig
				perClientContext.mu.Unlock()
			case management.ClientAuthDeny:
				reason := "authentication failed"
				if resp.Message != "" {
					reason = resp.Message
				}

				logger.InfoContext(p.ctx, "authentication denied",
					slog.String("reason", reason),
				)

				if err := openVPNClient.WriteToAuthFile("0"); err != nil {
					logger.ErrorContext(p.ctx, "write to auth file",
						slog.Any("err", err),
					)

					return
				}
			default:
				logger.ErrorContext(p.ctx, "unknown auth state")
			}
		}()

		return c.OpenVPNPluginFuncDeferred
	default:
		p.logger.ErrorContext(p.ctx, "unknown client auth response from management interface")

		return c.OpenVPNPluginFuncError
	}
}

// handleClientConnect handles the OPENVPN_PLUGIN_CLIENT_CONNECT_V2 event,
// which is triggered when a client attempts to establish a connection after authentication.
//
// This function checks the authentication state and:
//   - Returns DEFERRED if authentication is still pending
//   - Returns SUCCESS and optionally provides client-specific configuration if authenticated
//   - Returns ERROR if authentication was denied or state is invalid
//
// Parameters:
//   - perClientContext: Per-client context containing authentication state and config
//   - ret: Return structure where client-specific configuration can be set
//
// Returns:
//   - c.OpenVPNPluginFuncSuccess if client is authenticated and can connect
//   - c.OpenVPNPluginFuncError if authentication failed or context is invalid
//   - C.OPENVPN_PLUGIN_FUNC_DEFERRED if authentication is still pending
func (p *PluginHandle) handleClientConnect(perClientContext *ClientContext, ret *c.OpenVPNPluginArgsFuncReturn) c.OpenVPNPluginFuncStatus {
	if perClientContext == nil {
		p.logger.ErrorContext(p.ctx, "CLIENT_CONNECT_V2: missing perClientContext")

		return c.OpenVPNPluginFuncError
	}

	perClientContext.mu.Lock()
	defer perClientContext.mu.Unlock()

	if perClientContext.clientConfig == "" {
		return c.OpenVPNPluginFuncSuccess
	}

	if ret == nil || ret.ReturnList == nil {
		p.logger.ErrorContext(p.ctx, "CLIENT_CONNECT_V2: missing return_list")

		return c.OpenVPNPluginFuncError
	}

	returnList := (*c.OpenVPNPluginStringList)(
		C.calloc(1, C.size_t(unsafe.Sizeof(C.struct_openvpn_plugin_string_list{}))),
	)

	if returnList == nil {
		p.logger.ErrorContext(p.ctx, "malloc(return_list) failed")

		return c.OpenVPNPluginFuncError
	}

	returnList.Name = c.CString("config")
	returnList.Value = c.CString(perClientContext.clientConfig)

	*ret.ReturnList = returnList

	return c.OpenVPNPluginFuncSuccess
}

func (p *PluginHandle) handleClientDisconnect(clientEnvList **c.Char, perClientContext *ClientContext) c.OpenVPNPluginFuncStatus {
	perClientContext.mu.Lock()
	defer perClientContext.mu.Unlock()

	envArray, err := util.NewEnvList(clientEnvList)
	if err != nil {
		p.logger.ErrorContext(p.ctx, "parse env vars",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	openVPNClient, err := client.NewClient(perClientContext.clientID, envArray)
	if err != nil {
		p.logger.ErrorContext(p.ctx, "create OpenVPN client from env vars",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	err = p.managementClient.ClientDisconnect(openVPNClient.GetDisconnectMessage())
	if err != nil {
		p.logger.ErrorContext(p.ctx, "send client to management interface",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	return c.OpenVPNPluginFuncSuccess
}
