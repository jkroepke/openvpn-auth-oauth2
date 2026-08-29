//go:build (darwin || linux || openbsd || freebsd) && cgo

package testutil

/*
#cgo CFLAGS: -I../../../include
#include <openvpn-plugin.h>
#include <stdarg.h>
#include <stdio.h>

static void noop_plugin_log(openvpn_plugin_log_flags_t flags,
                            const char *module,
                            const char *fmt, ...)
{
    (void)flags; (void)module; (void)fmt;
}

struct openvpn_plugin_callbacks callbacks = {
    .plugin_log            = noop_plugin_log,
};

static char recorded_log[8192];

static void recording_plugin_log(openvpn_plugin_log_flags_t flags,
                                 const char *module,
                                 const char *fmt, ...)
{
    (void)flags; (void)module;

    va_list args;
    va_start(args, fmt);
    vsnprintf(recorded_log, sizeof(recorded_log), fmt, args);
    va_end(args);
}

struct openvpn_plugin_callbacks recording_callbacks = {
    .plugin_log            = recording_plugin_log,
};

static void reset_recorded_log(void)
{
    recorded_log[0] = '\0';
}

static const char *get_recorded_log(void)
{
    return recorded_log;
}
*/
import "C"

import (
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/internal/c"
)

func Callbacks() *c.OpenVPNPluginCallbacks {
	return (*c.OpenVPNPluginCallbacks)(unsafe.Pointer(&C.callbacks))
}

func RecordingCallbacks() *c.OpenVPNPluginCallbacks {
	C.reset_recorded_log()

	return (*c.OpenVPNPluginCallbacks)(unsafe.Pointer(&C.recording_callbacks))
}

func RecordedLog() string {
	return C.GoString(C.get_recorded_log())
}
