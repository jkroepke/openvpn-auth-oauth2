package c

/*
#cgo CFLAGS: -Wno-discarded-qualifiers -Wno-declaration-after-parameter -I../include
#include <openvpn-plugin.h>
*/
import "C"
import (
	"unsafe"
)

type Int = C.int
type Char = C.char
type SizeT = C.size_t

type OpenVPNPluginFuncStatus = Int

const (
	OpenVPNPluginFuncError    OpenVPNPluginFuncStatus = C.OPENVPN_PLUGIN_FUNC_ERROR
	OpenVPNPluginFuncSuccess  OpenVPNPluginFuncStatus = C.OPENVPN_PLUGIN_FUNC_SUCCESS
	OpenVPNPluginFuncDeferred OpenVPNPluginFuncStatus = C.OPENVPN_PLUGIN_FUNC_DEFERRED
)

type OpenVPNPluginInitPoint = Int

const OpenVPNPluginInitPreDaemon OpenVPNPluginInitPoint = C.OPENVPN_PLUGIN_INIT_PRE_DAEMON

type OpenVPNPluginArgsFuncIn = C.struct_openvpn_plugin_args_func_in
type OpenVPNPluginArgsFuncReturn = C.struct_openvpn_plugin_args_func_return
type OpenVPNPluginArgsOpenIn = C.struct_openvpn_plugin_args_open_in
type OpenVPNPluginArgsOpenReturn = C.struct_openvpn_plugin_args_open_return
type OpenVPNPluginCallbacks = C.struct_openvpn_plugin_callbacks
type OpenVPNPluginHandle = C.openvpn_plugin_handle_t
type OpenVPNPluginStringList = C.struct_openvpn_plugin_string_list

type PLogLevel = Int

const (
	PLogErr   PLogLevel = C.PLOG_ERR
	PLogWarn  PLogLevel = C.PLOG_WARN
	PLogNote  PLogLevel = C.PLOG_NOTE
	PLogDebug PLogLevel = C.PLOG_DEBUG
)

type OpenVPNPluginFuncType = Int

const (
	OpenVPNPluginUp                   OpenVPNPluginFuncType = C.OPENVPN_PLUGIN_UP
	OpenVPNPluginAuthUserPassVerify   OpenVPNPluginFuncType = C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY
	OpenVPNPluginClientConnectV2      OpenVPNPluginFuncType = C.OPENVPN_PLUGIN_CLIENT_CONNECT
	OpenVPNPluginClientConnectDeferV2 OpenVPNPluginFuncType = C.OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2
	OpenVPNPluginClientDisconnect     OpenVPNPluginFuncType = C.OPENVPN_PLUGIN_CLIENT_DISCONNECT
)

func Free(ptr unsafe.Pointer) {
	C.free(ptr)
}

func CString(str string) *Char {
	return C.CString(str)
}

func GoString(cstr *Char) string {
	return C.GoString(cstr)
}

func Malloc(size SizeT) unsafe.Pointer {
	return C.malloc(size)
}

func Calloc(num, size SizeT) unsafe.Pointer {
	return C.calloc(num, size)
}

func GetCallbacks(args *OpenVPNPluginArgsOpenIn) *OpenVPNPluginCallbacks {
	return args.callbacks
}

func SetTypeMask(ret *OpenVPNPluginArgsOpenReturn, mask Int) {
	ret.type_mask = mask
}

func GetArgs(args *OpenVPNPluginArgsOpenIn) **Char {
	return args.argv
}

func GetType(args *OpenVPNPluginArgsFuncIn) Int {
	return args._type
}

func GetEnvp(args *OpenVPNPluginArgsFuncIn) **Char {
	return args.envp
}

func GetPerClientContext(args *OpenVPNPluginArgsFuncIn) unsafe.Pointer {
	return args.per_client_context
}

func GetHandle(args *OpenVPNPluginArgsFuncIn) OpenVPNPluginHandle {
	return args.handle
}

func SetHandle(args *OpenVPNPluginArgsOpenReturn, handle OpenVPNPluginHandle) {
	args.handle = handle
}

func CreateStringList() *OpenVPNPluginStringList {
	// allocate one struct in C memory (zeroed)
	return (*OpenVPNPluginStringList)(
		Calloc(1, SizeT(unsafe.Sizeof(OpenVPNPluginStringList{}))),
	)
}

// SetStringListName sets the `name` field of a struct openvpn_plugin_string_list.
func SetStringListName(lst *OpenVPNPluginStringList, name string) {
	lst.name = CString(name)
}

// SetStringListValue sets the `value` field.
func SetStringListValue(lst *OpenVPNPluginStringList, value string) {
	lst.value = CString(value)
}

// GetReturnList gets the return_list pointer.
func GetReturnList(ret *OpenVPNPluginArgsFuncReturn) **OpenVPNPluginStringList {
	return ret.return_list
}

// SetReturnList sets the return_list pointer.
func SetReturnList(ret *OpenVPNPluginArgsFuncReturn, lst *OpenVPNPluginStringList) {
	*ret.return_list = lst
}
