//go:build linux

package main

/*
#cgo CFLAGS: -Wno-discarded-qualifiers -I/usr/include/openvpn/
#include <openvpn-plugin.h>

int openvpn_plugin_open_v3_go(int version, struct openvpn_plugin_args_open_in *arguments, struct openvpn_plugin_args_open_return *retptr);
int openvpn_plugin_func_v3_go(int version, struct openvpn_plugin_args_func_in *arguments, struct openvpn_plugin_args_func_return *retptr);

extern int openvpn_plugin_open_v3(const int version,
    struct openvpn_plugin_args_open_in const *arguments,
    struct openvpn_plugin_args_open_return *retptr
) {
	return openvpn_plugin_open_v3_go(version, arguments, retptr);
};

extern int openvpn_plugin_func_v3(const int version,
    struct openvpn_plugin_args_func_in const *arguments,
    struct openvpn_plugin_args_func_return *retptr
) {
	return openvpn_plugin_func_v3_go(version, arguments, retptr);
};
*/
import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

//goland:noinspection GoSnakeCaseUsage
const OPENVPN_PLUGIN_STRUCTVER_MIN = 5

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
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_select_initialization_point_v1() C.int {
	return C.OPENVPN_PLUGIN_INIT_POST_UID_CHANGE
}

// openvpn_plugin_min_version_required_v1
// This function is called by OpenVPN to query the minimum
// plugin interface version number required by the plugin.
//
//export openvpn_plugin_min_version_required_v1
//goland:noinspection GoSnakeCaseUsage
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

	handle := &PluginHandle{
		logger:           logger,
		managementClient: NewManagementClient(logger, listenSocketPassword),
	}

	handle.ctx, handle.cancel = context.WithCancel(context.Background())

	if err := handle.managementClient.Listen(handle.ctx, listenSocketAddr); err != nil {
		logger.Error(err.Error())

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	ret.handle = (C.openvpn_plugin_handle_t)(unsafe.Pointer(handle))

	logger.Info(fmt.Sprintf("plugin initialization done. version: %s", version))
	logger.Warn("THIS PLUGIN IS STILL IN EXPERIMENTAL STATE")

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

//export openvpn_plugin_func_v3_go
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_func_v3_go(v3structver C.int, args *C.struct_openvpn_plugin_args_func_in, _ *C.struct_openvpn_plugin_args_func_return) C.int {
	if v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN {
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	handle := (*PluginHandle)(unsafe.Pointer(args.handle))

	if args._type != C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY {
		handle.logger.Error("OPENVPN_PLUGIN_? called")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	client := NewClient(unsafe.Pointer(args.envp))

	if err := os.WriteFile(client.AuthPendingFile, []byte(pendingAuth), 0o600); err != nil {
		handle.logger.Error(fmt.Errorf("write to file %s: %w", client.AuthPendingFile, err).Error())
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	return C.OPENVPN_PLUGIN_FUNC_DEFERRED
}

//export openvpn_plugin_close_v1
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_close_v1(pluginHandle C.openvpn_plugin_handle_t) {
	handle := (*PluginHandle)(unsafe.Pointer(pluginHandle))
	if handle == nil {
		return
	}

	handle.managementClient.Close()

	handle.logger.Info("plugin closed")
}

//export openvpn_plugin_abort_v1
//goland:noinspection GoSnakeCaseUsage
func openvpn_plugin_abort_v1(pluginHandle C.openvpn_plugin_handle_t) {
	handle := (*PluginHandle)(unsafe.Pointer(pluginHandle))
	if handle == nil {
		return
	}

	handle.managementClient.Close()

	handle.logger.Info("plugin abort")
}
