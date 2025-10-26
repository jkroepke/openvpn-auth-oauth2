package main

/*
#cgo CFLAGS: -Wno-discarded-qualifiers -I./include
#include <openvpn-plugin.h>

int openvpn_plugin_open_v3_go(
    int version,
    const struct openvpn_plugin_args_open_in *arguments,
    struct openvpn_plugin_args_open_return *retptr
);

int openvpn_plugin_func_v3_go(
    int version,
    const struct openvpn_plugin_args_func_in *arguments,
    struct openvpn_plugin_args_func_return *retptr
);

extern int openvpn_plugin_open_v3(
    const int version,
    const struct openvpn_plugin_args_open_in *arguments,
    struct openvpn_plugin_args_open_return *retptr
) {
    return openvpn_plugin_open_v3_go(version, arguments, retptr);
}

extern int openvpn_plugin_func_v3(
    const int version,
    const struct openvpn_plugin_args_func_in *arguments,
    struct openvpn_plugin_args_func_return *retptr
) {
    return openvpn_plugin_func_v3_go(version, arguments, retptr);
}

*/
import "C"
import (
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/plugin"
)

// main function as required by Go for building a shared library.
func main() {
	// This function is here to satisfy Go's requirement of having a main function.
	// The main functionality is implemented in the openvpn_plugin_open_v3 function,
	// which will be called from C.
}

// openvpn_plugin_select_initialization_point_v1
//
// Several points exist in OpenVPNs initialization sequence where
// the openvpn_plugin_open function can be called. While the default is
// OPENVPN_PLUGIN_INIT_PRE_DAEMON, this function can be used to select a
// different initialization point. For example, if the plugin needs to
// return configuration parameters to OpenVPN, use
// OPENVPN_PLUGIN_INIT_PRE_CONFIG_PARSE.
//
//export openvpn_plugin_select_initialization_point_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_select_initialization_point_v1() c.Int {
	return c.OpenVPNPluginInitPreDaemon
}

// openvpn_plugin_min_version_required_v1
// This function is called by OpenVPN to query the minimum
// plugin interface version number required by the plugin.
//
//export openvpn_plugin_min_version_required_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_min_version_required_v1() c.Int {
	return plugin.OpenVPNPluginVerMin
}

// OpenVPNPluginOpenV3 is called by OpenVPN when the plugin is loaded.
// It initializes the plugin, sets up the management interface, and registers
// the plugin event types that this plugin will handle.
//
// Parameters:
//   - v3structver: The OpenVPN plugin API structure version
//   - args: Plugin initialization arguments including argv and callbacks
//   - ret: Return structure where the plugin sets the type_mask and handle
//
// Returns:
//   - c.OpenVPNPluginFuncSuccess on successful initialization
//   - c.OpenVPNPluginFuncError on failure
//
// The function expects plugin arguments in the format:
//
//	openvpn-auth-oauth2.so <listen socket> [<password-file>]
//
//export openvpn_plugin_open_v3_go
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_open_v3_go(v3structver c.Int, args *c.OpenVPNPluginArgsOpenIn, ret *c.OpenVPNPluginArgsOpenReturn) c.Int {
	return plugin.OpenvpnPluginOpenV3(v3structver, args, ret)
}

// openvpn_plugin_func_v3_go is the main plugin callback function called by OpenVPN
// when plugin events occur. It routes events to the appropriate handler based on
// the event type.
//
//export openvpn_plugin_func_v3_go
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_func_v3_go(v3structver c.Int, args *c.OpenVPNPluginArgsFuncIn, ret *c.OpenVPNPluginArgsFuncReturn) c.OpenVPNPluginFuncStatus {
	return plugin.OpenVPMPluginFuncV3(v3structver, args, ret)
}

// openvpn_plugin_close_v1 is called by OpenVPN when the plugin is being unloaded.
// It performs cleanup operations including closing the management client connection
// and freeing the plugin handle.
//
// Parameters:
//   - handlePtr: Pointer to the global plugin context handle
//
//export openvpn_plugin_close_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_close_v1(handlePtr c.OpenVPNPluginHandle) {
	plugin.OpenVPNPluginCloseV1(handlePtr)
}

// openvpn_plugin_client_constructor_v1 is called by OpenVPN when a new client connects.
// It creates and returns a per-client context that will be passed to subsequent plugin
// callbacks for this specific client.
//
// The per-client context stores authentication state and client-specific configuration
// that persists throughout the client's connection lifecycle.
//
// Parameters:
//   - handlePtr: Pointer to the global plugin context handle
//
// Returns:
//   - unsafe.Pointer containing a cgo.Handle to the new clientContext
//
//export openvpn_plugin_client_constructor_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_client_constructor_v1(handlePtr c.OpenVPNPluginHandle) unsafe.Pointer {
	return plugin.OpenVPNPluginClientConstructorV1(handlePtr)
}

// openvpn_plugin_client_destructor_v1 is called by OpenVPN when a client disconnects.
// It performs cleanup operations for the per-client context, freeing the cgo.Handle
// and allowing the Go garbage collector to reclaim the clientContext memory.
//
// Parameters:
//   - handlePtr: Pointer to the global plugin context handle
//   - perClientContext: The per-client context handle to be destroyed
//
//export openvpn_plugin_client_destructor_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_client_destructor_v1(handlePtr c.OpenVPNPluginHandle, perClientContext unsafe.Pointer) {
	plugin.OpenVPNPluginClientDestructorV1(handlePtr, perClientContext)
}

// openvpn_plugin_abort_v1 is called by OpenVPN when an abort signal is received or
// when OpenVPN needs to terminate unexpectedly. It performs emergency cleanup operations
// including closing the management client and freeing the plugin handle.
//
// Parameters:
//   - handlePtr: Pointer to the global plugin context handle
//
//export openvpn_plugin_abort_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_abort_v1(handlePtr c.OpenVPNPluginHandle) {
	plugin.OpenVPNPluginAbortV1(handlePtr)
}
