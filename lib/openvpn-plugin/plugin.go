//go:build linux

package main

/*
#include <openvpn-plugin.h>
*/
import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/cgo"
	"sync/atomic"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/version"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-plugin/client"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-plugin/management"
)

//goland:noinspection GoSnakeCaseUsage
//nolint:revive
const OPENVPN_PLUGIN_STRUCTVER_MIN = 5

// clientID is a global counter for client IDs, incremented atomically.
//
//nolint:gochecknoglobals
var clientID uint64

// openvpn_plugin_select_initialization_point_v1
//
// Several different points exist in OpenVPN's initialization sequence where
// the openvpn_plugin_open function can be called. While the default is
// OPENVPN_PLUGIN_INIT_PRE_DAEMON, this function can be used to select a
// different initialization point.  For example, if your plugin needs to
// return configuration parameters to OpenVPN, use
// OPENVPN_PLUGIN_INIT_PRE_CONFIG_PARSE.
//
//export openvpn_plugin_select_initialization_point_v1
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_select_initialization_point_v1() C.int {
	return C.OPENVPN_PLUGIN_INIT_POST_UID_CHANGE
}

// openvpn_plugin_min_version_required_v1
// This function is called by OpenVPN to query the minimum
// plugin interface version number required by the plugin.
//
//export openvpn_plugin_min_version_required_v1
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_min_version_required_v1() C.int {
	return 3
}

//export openvpn_plugin_open_v3_go
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_open_v3_go(v3structver C.int, args *C.struct_openvpn_plugin_args_open_in, ret *C.struct_openvpn_plugin_args_open_return) C.int {
	if v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN {
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	ret.type_mask = 1<<C.OPENVPN_PLUGIN_UP |
		1<<C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY |
		1<<C.OPENVPN_PLUGIN_CLIENT_CONNECT_V2 |
		1<<C.OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2

	pluginArgs := unsafe.Slice(args.argv, 2)

	logger := slog.New(NewOpenVPNPluginLogger(args.callbacks, nil))

	if len(pluginArgs) > 3 || len(pluginArgs) < 2 {
		logger.Error("Invalid amount of arguments! openvpn-auth-oauth2.so <listen socket> [<password>]")

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	listenSocketAddr := C.GoString(pluginArgs[1])

	var listenSocketPassword string
	if len(pluginArgs) == 3 {
		listenSocketPassword = C.GoString(pluginArgs[2])
	}

	ctx := context.Background()

	handle := cgo.NewHandle(unsafe.Pointer(&pluginHandle{
		logger:           logger,
		managementClient: management.NewServer(logger, listenSocketPassword),
		ctx:              ctx,
		listenSocketAddr: listenSocketAddr,
	}))

	ret.handle = (C.openvpn_plugin_handle_t)(unsafe.Pointer(handle))

	logger.InfoContext(ctx, "plugin initialization done",
		slog.String("version", version.Version),
	)

	logger.WarnContext(ctx, "THIS PLUGIN IS STILL IN EXPERIMENTAL STATE")

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

//export openvpn_plugin_func_v3_go
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_func_v3_go(v3structver C.int, args *C.struct_openvpn_plugin_args_func_in, ret *C.struct_openvpn_plugin_args_func_return) C.int {
	if v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN {
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	// args
	// Arguments used to transport variables to and from the
	// plug-in. The struct openvpn_plugin_args_func is only used
	// by the openvpn_plugin_func_v3() function.
	//
	// STRUCT MEMBERS:
	//
	// type: one of the PLUGIN_x types.
	//
	// argv: a NULL-terminated array of “command line” options which
	//        would normally be passed to the script.  argv[0] is the dynamic
	//        library pathname.
	//
	// envp: a NULL-terminated array of OpenVPN-set environmental
	//        variables in "name=value" format. Note that for security reasons,
	//        these variables are not written to the "official"
	//        environmental variable store of the process.
	//
	// handle: Pointer to a global plug-in context, created by the plug-in's openvpn_plugin_open_v3().
	//
	// per_client_context: the per-client context pointer, which was returned by
	//        openvpn_plugin_client_constructor_v1, if defined.

	handle, ok := cgo.NewHandle(unsafe.Pointer(args.handle)).Value().(*pluginHandle)
	if !ok {
		panic("openvpn_plugin_func_v3: invalid plugin handle type")
	}

	perClientContext, ok := cgo.NewHandle(unsafe.Pointer(args.per_client_context)).Value().(*clientContext) //nolint:unconvert
	if !ok && args.per_client_context != nil {
		handle.logger.ErrorContext(handle.ctx, "invalid per_client_context type")

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	switch args._type {
	case C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
		return handle.handleAuthUserPassVerify(unsafe.Pointer(args.envp), perClientContext)
	case C.OPENVPN_PLUGIN_CLIENT_CONNECT_V2:
		return handle.handleClientConnect(perClientContext, ret)
	case C.OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2:
		return handle.handleClientConnectDefer(perClientContext, ret)
	case C.OPENVPN_PLUGIN_UP:
		return handle.handlePluginUp()
	default:
		handle.logger.ErrorContext(handle.ctx, fmt.Sprintf("unhandled OPENVPN_PLUGIN event: %d", args._type))

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}
}

func (p *pluginHandle) handlePluginUp() C.int {
	if err := p.managementClient.Listen(p.ctx, p.listenSocketAddr); err != nil {
		p.logger.ErrorContext(p.ctx, "failed to start management client: ",
			slog.Any("err", err),
		)

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

//nolint:cyclop
func (p *pluginHandle) handleAuthUserPassVerify(envp unsafe.Pointer, perClientContext *clientContext) C.int {
	envArray, err := NewEnvList(envp)
	if err != nil {
		p.logger.ErrorContext(p.ctx, "parse env vars",
			slog.Any("err", err),
		)

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	sessionID, ok := envArray["session_id"]
	if !ok {
		p.logger.ErrorContext(p.ctx, "missing session_id in env vars")

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	clientID := atomic.AddUint64(&clientID, 1)

	logger := p.logger.With(
		slog.Uint64("client_id", clientID),
		slog.String("session_id", sessionID),
	)

	logger.DebugContext(p.ctx, "env", slog.Any("env", envArray))

	openVPNClient, err := client.NewClient(clientID, envArray)
	if err != nil {
		logger.ErrorContext(p.ctx, "create OpenVPN client from env vars",
			slog.Any("err", err),
		)

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	resp, err := p.managementClient.ClientAuth(openVPNClient.String())
	if err != nil {
		logger.ErrorContext(p.ctx, "send client to management interface",
			slog.Any("err", err),
		)

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	perClientContext.mu.Lock()
	perClientContext.authState = resp.ClientAuth
	perClientContext.mu.Unlock()

	switch resp.ClientAuth {
	case management.ClientAuthAccept:
		if err := p.writeToAuthFile(openVPNClient, "1"); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)

			return C.OPENVPN_PLUGIN_FUNC_ERROR
		}

		perClientContext.mu.Lock()
		perClientContext.clientConfig = resp.ClientConfig
		perClientContext.mu.Unlock()

		return C.OPENVPN_PLUGIN_FUNC_SUCCESS
	case management.ClientAuthDeny:
		reason := "authentication failed"
		if resp.Message != "" {
			reason = resp.Message
		}

		if err := p.writeToAuthFile(openVPNClient, "0\n"+reason); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)
		}

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	case management.ClientAuthPending:
		// Write "2" to auth control file to indicate deferred auth
		if err := p.writeAuthPending(openVPNClient, resp); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)

			return C.OPENVPN_PLUGIN_FUNC_ERROR
		}

		defer func() {
			authState, clientConfig, err := p.managementClient.AuthPendingPoller(clientID)
			if perClientContext != nil {
				perClientContext.mu.Lock()
				perClientContext.authState = authState
				perClientContext.clientConfig = clientConfig
				perClientContext.mu.Unlock()
			}

			if err != nil {
				logger.ErrorContext(p.ctx, "poll deferred auth state",
					slog.Any("err", err),
				)

				return
			}
		}()

		return C.OPENVPN_PLUGIN_FUNC_DEFERRED
	default:
		p.logger.ErrorContext(p.ctx, "unknown client auth response from management interface")

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}
}

func (p *pluginHandle) handleClientConnect(perClientContext *clientContext, ret *C.struct_openvpn_plugin_args_func_return) C.int {
	if perClientContext == nil {
		p.logger.ErrorContext(p.ctx, "CLIENT_CONNECT_V2: missing perClientContext")

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	perClientContext.mu.Lock()
	if perClientContext.authState != management.ClientAuthPending {
		perClientContext.mu.Unlock()

		return C.OPENVPN_PLUGIN_FUNC_DEFERRED
	}

	if perClientContext.clientConfig != "" {
		if ret == nil || ret.return_list == nil {
			p.logger.ErrorContext(p.ctx, "CLIENT_CONNECT_V2: missing return_list")

			return C.OPENVPN_PLUGIN_FUNC_ERROR
		}

		// allocate one struct in C memory (zeroed)
		returnList := (*C.struct_openvpn_plugin_string_list)(
			C.calloc(1, C.size_t(unsafe.Sizeof(C.struct_openvpn_plugin_string_list{}))),
		)
		if returnList == nil {
			p.logger.ErrorContext(p.ctx, "malloc(return_list) failed")

			return C.OPENVPN_PLUGIN_FUNC_ERROR
		}

		returnList.name = C.CString("config")
		returnList.value = C.CString(perClientContext.clientConfig)

		*ret.return_list = returnList
	}

	perClientContext.mu.Unlock()

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

//goland:noinspection GoUnusedParameter
func (p *pluginHandle) handleClientConnectDefer(perClientContext *clientContext, ret *C.struct_openvpn_plugin_args_func_return) C.int {
	return p.handleClientConnect(perClientContext, ret)
}

//export openvpn_plugin_close_v1
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_close_v1(handlePtr C.openvpn_plugin_handle_t) {
	handle, ok := cgo.NewHandle(unsafe.Pointer(handlePtr)).Value().(*pluginHandle)
	if !ok {
		panic("openvpn_plugin_close_v1: invalid plugin handle type")
	}

	handle.managementClient.Close()

	handle.logger.InfoContext(handle.ctx, "plugin closed")

	h := cgo.Handle(handlePtr)
	h.Delete() // frees handle, allows GC to collect Go object
}

//export openvpn_plugin_client_constructor_v1
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_client_constructor_v1(handlePtr C.openvpn_plugin_handle_t) unsafe.Pointer {
	handle, ok := cgo.NewHandle(unsafe.Pointer(handlePtr)).Value().(*pluginHandle)
	if !ok {
		panic("openvpn_plugin_client_constructor_v1: invalid plugin handle type")
	}

	handle.logger.DebugContext(handle.ctx, "openvpn_plugin_client_constructor_v1: called")

	clientHandle := cgo.NewHandle(&clientContext{})

	return unsafe.Pointer(clientHandle)
}

//export openvpn_plugin_client_destructor_v1
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_client_destructor_v1(handlePtr C.openvpn_plugin_handle_t, perClientContext unsafe.Pointer) {
	handle, ok := cgo.NewHandle(unsafe.Pointer(handlePtr)).Value().(*pluginHandle)
	if !ok {
		panic("openvpn_plugin_client_destructor_v1: invalid plugin handle type")
	}

	handle.logger.DebugContext(handle.ctx, "openvpn_plugin_client_destructor_v1: called")

	h := cgo.Handle(perClientContext)
	h.Delete() // frees handle, allows GC to collect Go object
}

//export openvpn_plugin_abort_v1
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_abort_v1(handlePtr C.openvpn_plugin_handle_t) {
	handle, ok := cgo.NewHandle(unsafe.Pointer(handlePtr)).Value().(*pluginHandle)
	if !ok {
		panic("openvpn_plugin_abort_v1: invalid plugin handle type")
	}

	handle.managementClient.Close()

	h := cgo.Handle(handlePtr)
	h.Delete() // frees handle, allows GC to collect Go object

	handle.logger.WarnContext(handle.ctx, "plugin abort")
}
