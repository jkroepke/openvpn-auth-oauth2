package main

/*
#include <openvpn-plugin.h>
*/
import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime/cgo"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/version"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/client"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util"
)

//goland:noinspection GoSnakeCaseUsage
//nolint:revive
const OPENVPN_PLUGIN_STRUCTVER_MIN = 5

// clientIDCounter is a global counter for client IDs, incremented atomically.
//
//nolint:gochecknoglobals
var clientIDCounter uint64

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
	return C.OPENVPN_PLUGIN_INIT_PRE_DAEMON
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

	pluginArgs := ArgvToStrings(args.argv)

	logger := slog.New(NewOpenVPNPluginLogger(args.callbacks, nil))

	if len(pluginArgs) > 3 || len(pluginArgs) < 2 {
		logger.Error("Invalid amount of arguments! openvpn-auth-oauth2.so <listen socket> [<password-file>]")

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	listenSocketAddr := pluginArgs[1]

	var listenSocketPassword string

	if len(pluginArgs) == 3 {
		password, err := os.ReadFile(pluginArgs[2])
		if err != nil {
			logger.Error("Failed to read password file",
				slog.Any("err", err),
			)

			return C.OPENVPN_PLUGIN_FUNC_ERROR
		}

		listenSocketPassword = strings.TrimSpace(string(password))
	}
	ctx := context.Background()

	handle := cgo.NewHandle(&pluginHandle{
		logger:           logger,
		managementClient: management.NewServer(logger, listenSocketPassword),
		ctx:              ctx,
		listenSocketAddr: listenSocketAddr,
	})

	ret.handle = (C.openvpn_plugin_handle_t)(unsafe.Pointer(&handle))

	logger.InfoContext(ctx, "plugin loaded",
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

	handle, ok := (*(*cgo.Handle)(unsafe.Pointer(args.handle))).Value().(*pluginHandle)
	if !ok {
		panic("openvpn_plugin_func_v3: invalid plugin handle type")
	}

	var perClientContext *clientContext

	if args._type != C.OPENVPN_PLUGIN_UP {
		perClientContext, ok = cgo.Handle(args.per_client_context).Value().(*clientContext)
		if !ok {
			handle.logger.ErrorContext(handle.ctx, "invalid per_client_context type")

			return C.OPENVPN_PLUGIN_FUNC_ERROR
		}
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
		p.logger.ErrorContext(p.ctx, "failed to start management client",
			slog.Any("err", err),
		)

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	p.logger.InfoContext(p.ctx, "listener started",
		slog.Any("addr", p.listenSocketAddr),
	)

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

//nolint:cyclop
func (p *pluginHandle) handleAuthUserPassVerify(envp unsafe.Pointer, perClientContext *clientContext) C.int {
	envArray, err := util.NewEnvList(envp)
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

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	resp, err := p.managementClient.ClientAuth(currentClientID, openVPNClient.String())
	if err != nil {
		logger.ErrorContext(p.ctx, "send client to management interface",
			slog.Any("err", err),
		)

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	perClientContext.mu.Lock()
	perClientContext.authState = resp.ClientAuth
	perClientContext.mu.Unlock()

	logger.InfoContext(p.ctx, "client auth response: "+resp.ClientAuth.String())

	switch resp.ClientAuth {
	case management.ClientAuthAccept:
		if err := openVPNClient.WriteToAuthFile("1"); err != nil {
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

		if err := openVPNClient.WriteToAuthFile("0\n" + reason); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)
		}

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	case management.ClientAuthPending:
		// Write "2" to auth control file to indicate deferred auth
		if err := openVPNClient.WriteAuthPending(resp); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)

			return C.OPENVPN_PLUGIN_FUNC_ERROR
		}

		go func() {
			resp, err := p.managementClient.AuthPendingPoller(currentClientID, 5*time.Minute)
			if err != nil {
				logger.ErrorContext(p.ctx, "poll deferred auth state",
					slog.Any("err", err),
				)

				return
			}

			if perClientContext != nil {
				perClientContext.mu.Lock()
				perClientContext.authState = resp.ClientAuth
				perClientContext.clientConfig = resp.ClientConfig
				perClientContext.mu.Unlock()
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
	defer perClientContext.mu.Unlock()

	switch perClientContext.authState {
	case management.ClientAuthPending:
		return C.OPENVPN_PLUGIN_FUNC_DEFERRED
	case management.ClientAuthAccept:
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

		return C.OPENVPN_PLUGIN_FUNC_SUCCESS
	case management.ClientAuthDeny:
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	default:
		p.logger.ErrorContext(p.ctx, "CLIENT_CONNECT_V2: unexpected auth state",
			slog.Any("state", perClientContext.authState),
		)

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}
}

//goland:noinspection GoUnusedParameter
func (p *pluginHandle) handleClientConnectDefer(perClientContext *clientContext, ret *C.struct_openvpn_plugin_args_func_return) C.int {
	return p.handleClientConnect(perClientContext, ret)
}

//export openvpn_plugin_close_v1
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_close_v1(handlePtr C.openvpn_plugin_handle_t) {
	handle, ok := (*(*cgo.Handle)(handlePtr)).Value().(*pluginHandle)
	if !ok {
		panic("openvpn_plugin_close_v1: invalid plugin handle type")
	}

	handle.managementClient.Close()

	handle.logger.InfoContext(handle.ctx, "plugin closed")

	(*(*cgo.Handle)(handlePtr)).Delete() // frees handle, allows GC to collect Go object
}

//export openvpn_plugin_client_constructor_v1
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_client_constructor_v1(handlePtr C.openvpn_plugin_handle_t) unsafe.Pointer {
	handle, ok := (*(*cgo.Handle)(handlePtr)).Value().(*pluginHandle)
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
	handle, ok := (*(*cgo.Handle)(handlePtr)).Value().(*pluginHandle)
	if !ok {
		panic("openvpn_plugin_client_destructor_v1: invalid plugin handle type")
	}

	handle.logger.DebugContext(handle.ctx, "openvpn_plugin_client_destructor_v1: called")

	cgo.Handle(perClientContext).Delete() // frees handle, allows GC to collect Go object
}

//export openvpn_plugin_abort_v1
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_abort_v1(handlePtr C.openvpn_plugin_handle_t) {
	handle, ok := (*(*cgo.Handle)(handlePtr)).Value().(*pluginHandle)
	if !ok {
		panic("openvpn_plugin_abort_v1: invalid plugin handle type")
	}

	handle.managementClient.Close()

	// frees handle, allows GC to collect Go object
	(*(*cgo.Handle)(handlePtr)).Delete()

	handle.logger.WarnContext(handle.ctx, "plugin abort")
}
