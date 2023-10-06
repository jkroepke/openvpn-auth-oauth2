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
