//go:build (linux || openbsd || freebsd) && cgo

package main

/*
#cgo CFLAGS: -I./include
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
	"runtime/debug"
)

// memoryLimit is the soft memory limit for the Go runtime (256 MiB).
// Because this plugin runs inside the OpenVPN server process, a bounded
// heap prevents the Go GC from consuming too much of the host's memory.
const memoryLimit int64 = 256 * 1024 * 1024

// main function as required by Go for building a shared library.
func main() {
	// This function is here to satisfy Go's requirement of having a main function.
	// The main functionality is implemented in the openvpn_plugin_open_v3 function,
	// which will be called from C.

	debug.SetMemoryLimit(memoryLimit)
}
