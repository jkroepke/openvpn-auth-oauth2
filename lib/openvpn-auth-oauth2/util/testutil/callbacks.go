//go:build linux && cgo

package testutil

/*
#cgo CFLAGS: -I../../include
#include <openvpn-plugin.h>

static void noop_plugin_log(openvpn_plugin_log_flags_t flags,
                            const char *module,
                            const char *fmt, ...)
{
    (void)flags; (void)module; (void)fmt;
}

struct openvpn_plugin_callbacks callbacks = {
    .plugin_log            = noop_plugin_log,
};
*/
import "C"

import (
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
)

func Callbacks() *c.OpenVPNPluginCallbacks {
	return (*c.OpenVPNPluginCallbacks)(unsafe.Pointer(&C.callbacks))
}
