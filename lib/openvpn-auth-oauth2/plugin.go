package main

/*
#cgo CFLAGS: -I./include
#include <openvpn-plugin.h>
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/openvpn"
)

// openvpn_plugin_select_initialization_point_v1
//
// Several points exist in OpenVPNs initialization sequence where
// the openvpn_plugin_open function can be called.
//
//export openvpn_plugin_select_initialization_point_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_select_initialization_point_v1() C.int {
	return C.int(c.OpenVPNPluginInitPreDaemon)
}

// openvpn_plugin_min_version_required_v1
// This function is called by OpenVPN to query the minimum
// plugin interface version number required by the plugin.
//
//export openvpn_plugin_min_version_required_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_min_version_required_v1() C.int {
	return C.int(openvpn.PluginVerMin)
}

// OpenVPNPluginOpenV3 is called by OpenVPN when the plugin is loaded.
// It initializes the plugin, sets up the management interface, and registers
// the plugin event types that this plugin will handle.
//
// Parameters:
//   - v3structver: The OpenVPN Plugin API structure version
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
func openvpn_plugin_open_v3_go(v3structver C.int, args *C.struct_openvpn_plugin_args_open_in, ret *C.struct_openvpn_plugin_args_open_return) C.int {
	return C.int(openvpn.PluginOpenV3(
		int(v3structver),
		(*c.OpenVPNPluginArgsOpenIn)(unsafe.Pointer(args)),
		(*c.OpenVPNPluginArgsOpenReturn)(unsafe.Pointer(ret)),
	))
}

// openvpn_plugin_func_v3_go is the main plugin callback function called by OpenVPN
// when plugin events occur. It routes events to the appropriate handler based on
// the event type.
//
//export openvpn_plugin_func_v3_go
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_func_v3_go(v3structver C.int, args *C.struct_openvpn_plugin_args_func_in, ret *C.struct_openvpn_plugin_args_func_return) C.int {
	return C.int(openvpn.PluginFuncV3(
		int(v3structver),
		(*c.OpenVPNPluginArgsFuncIn)(unsafe.Pointer(args)),
		(*c.OpenVPNPluginArgsFuncReturn)(unsafe.Pointer(ret)),
	))
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
func openvpn_plugin_close_v1(handlePtr C.openvpn_plugin_handle_t) {
	openvpn.PluginCloseV1(c.OpenVPNPluginHandle(handlePtr))
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
func openvpn_plugin_client_constructor_v1(handlePtr C.openvpn_plugin_handle_t) unsafe.Pointer {
	return unsafe.Pointer(openvpn.PluginClientConstructorV1(c.OpenVPNPluginHandle(handlePtr)))
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
func openvpn_plugin_client_destructor_v1(handlePtr C.openvpn_plugin_handle_t, perClientContext unsafe.Pointer) {
	openvpn.PluginClientDestructorV1(
		c.OpenVPNPluginHandle(handlePtr),
		(*cgo.Handle)(perClientContext),
	)
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
func openvpn_plugin_abort_v1(handlePtr C.openvpn_plugin_handle_t) {
	openvpn.PluginAbortV1(c.OpenVPNPluginHandle(handlePtr))
}
