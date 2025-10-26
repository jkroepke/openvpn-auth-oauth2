package c

/*
#cgo CFLAGS: -Wno-discarded-qualifiers -Wno-declaration-after-parameter -I../include
#include <openvpn-plugin.h>
static char *MODULE = "openvpn-auth-oauth2";

// A wrapper function is needed because go is not able to call C pointer functions
// https://stackoverflow.com/questions/37157379/passing-function-pointer-to-the-c-code-using-cgo
int plugin_log(struct openvpn_plugin_callbacks* cb, int flags, char *msg) {
	cb->plugin_log(flags, MODULE, "%s", msg);
	return 0;
}
*/
import "C"

import (
	"unsafe"
)

func PluginLog(cb *OpenVPNPluginCallbacks, flags PLogLevel, msg *Char) {
	//nolint:nlreturn,unconvert // false positive
	C.plugin_log((*C.struct_openvpn_plugin_callbacks)(unsafe.Pointer(cb)), C.int(flags), (*C.char)(msg))
}
