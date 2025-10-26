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

// main function as required by Go for building a shared library.
func main() {
	// This function is here to satisfy Go's requirement of having a main function.
	// The main functionality is implemented in the openvpn_plugin_open_v3 function,
	// which will be called from C.
}
