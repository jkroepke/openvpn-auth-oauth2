package c

/*
#cgo CFLAGS: -Wno-discarded-qualifiers -Wno-declaration-after-parameter -I../include
#include <openvpn-plugin.h>
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

type (
	Int  = int
	Char = C.char
)

type OpenVPNPluginFuncStatus = Int

const (
	OpenVPNPluginFuncError    OpenVPNPluginFuncStatus = C.OPENVPN_PLUGIN_FUNC_ERROR
	OpenVPNPluginFuncSuccess  OpenVPNPluginFuncStatus = C.OPENVPN_PLUGIN_FUNC_SUCCESS
	OpenVPNPluginFuncDeferred OpenVPNPluginFuncStatus = C.OPENVPN_PLUGIN_FUNC_DEFERRED
)

type OpenVPNPluginInitPoint = Int

const OpenVPNPluginInitPreDaemon OpenVPNPluginInitPoint = C.OPENVPN_PLUGIN_INIT_PRE_DAEMON

type OpenVPNPluginArgsOpenIn struct {
	TypeMask         C.int
	Argv             **C.char
	Envp             **C.char
	Callbacks        *OpenVPNPluginCallbacks
	SSLApi           C.int
	OVPNVersion      *C.char
	OVPNVersionMajor C.uint
	OVPNVersionMinor C.uint
	OVPNVersionPatch *C.char
}

type OpenVPNPluginArgsOpenReturn struct {
	TypeMask   C.int
	Handle     OpenVPNPluginHandle
	ReturnList **OpenVPNPluginStringList
}

type OpenVPNPluginArgsFuncIn struct {
	Type             C.int
	Argv             **C.char
	Envp             **C.char
	Handle           OpenVPNPluginHandle
	PerClientContext OpenVPNPluginClientContext
	CurrentCertDepth C.int
	CurrentCert      unsafe.Pointer // *C.openvpn_x509_cert_t
}

type OpenVPNPluginArgsFuncReturn struct {
	ReturnList **OpenVPNPluginStringList
}

type OpenVPNPluginCallbacks struct {
	PluginLog           unsafe.Pointer // plugin_log_t
	PluginVLog          unsafe.Pointer // plugin_vlog_t
	PluginSecureMemzero unsafe.Pointer // plugin_secure_memzero_t
	PluginBase64Encode  unsafe.Pointer // plugin_base64_encode_t
	PluginBase64Decode  unsafe.Pointer // plugin_base64_decode_t
}

type OpenVPNPluginStringList struct {
	Next  *OpenVPNPluginStringList
	Name  *C.char
	Value *C.char
}

type (
	OpenVPNPluginHandle        = *cgo.Handle
	OpenVPNPluginClientContext = unsafe.Pointer
)

type PLogLevel = Int

const (
	PLogErr   PLogLevel = C.PLOG_ERR
	PLogWarn  PLogLevel = C.PLOG_WARN
	PLogNote  PLogLevel = C.PLOG_NOTE
	PLogDebug PLogLevel = C.PLOG_DEBUG
)

type OpenVPNPluginFuncType = C.int

const (
	OpenVPNPluginUp                 OpenVPNPluginFuncType = C.OPENVPN_PLUGIN_UP
	OpenVPNPluginAuthUserPassVerify OpenVPNPluginFuncType = C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY
	OpenVPNPluginClientConnectV2    OpenVPNPluginFuncType = C.OPENVPN_PLUGIN_CLIENT_CONNECT_V2
	OpenVPNPluginClientDisconnect   OpenVPNPluginFuncType = C.OPENVPN_PLUGIN_CLIENT_DISCONNECT
)

func CString(str string) *Char {
	return C.CString(str)
}

func GoString(cstr *Char) string {
	return C.GoString(cstr)
}
