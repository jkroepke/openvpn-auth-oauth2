package main

/*
#include "openvpn-plugin.h"
*/
import "C"
import (
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
)

const OPENVPN_PLUGIN_STRUCTVER_MIN = 5

//export openvpn_plugin_select_initialization_point_v1
func openvpn_plugin_select_initialization_point_v1() C.int {
	return 2
}

//export openvpn_plugin_min_version_required_v1
func openvpn_plugin_min_version_required_v1() C.int {
	return 3
}

//export openvpn_plugin_open_v3_go
func openvpn_plugin_open_v3_go(v3structver C.int, args *C.struct_openvpn_plugin_args_open_in, retptr *C.struct_openvpn_plugin_args_open_return) C.int {
	if v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN {
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	retptr.type_mask = 1 << C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY

	pluginArgs := unsafe.Slice(args.argv, 2)

	logger := slog.New(New(args.callbacks, nil))

	if len(pluginArgs) > 2 {
		logger.Error("Multiple args declared! One one argument supported!")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	if len(pluginArgs) < 2 {
		logger.Error("Missing arguments!")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	configFile := C.GoString(pluginArgs[1])
	conf, err := config.Load(config.Plugin, configFile, nil)
	if err != nil {
		logger.Error(fmt.Errorf("error loading config: %w", err).Error())

		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	provider, err := oauth2.NewProvider(logger, conf)
	if err != nil {
		logger.Error(err.Error())

		return 1
	}

	handle := &PluginHandle{
		logger:   logger,
		conf:     conf,
		provider: provider,
	}
	retptr.handle = (C.openvpn_plugin_handle_t)(unsafe.Pointer(handle))

	logger.Info("plugin initialization done")

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

//export openvpn_plugin_func_v3_go
func openvpn_plugin_func_v3_go(v3structver C.int, args *C.struct_openvpn_plugin_args_func_in, _ *C.struct_openvpn_plugin_args_func_return) C.int {
	if v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN {
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	pluginHandle := (*PluginHandle)(unsafe.Pointer(args.handle))

	if args._type != C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY {
		pluginHandle.logger.Error("OPENVPN_PLUGIN_? called")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	pluginHandle.logger.Info("new clients")

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

//export openvpn_plugin_close_v1
func openvpn_plugin_close_v1(handle C.openvpn_plugin_handle_t) {
	pluginHandle := (*PluginHandle)(unsafe.Pointer(handle))
	if pluginHandle == nil {
		return
	}

	pluginHandle.logger.Info("plugin closed")
}

//export openvpn_plugin_abort_v1
func openvpn_plugin_abort_v1(handle C.openvpn_plugin_handle_t) {
	pluginHandle := (*PluginHandle)(unsafe.Pointer(handle))
	if pluginHandle == nil {
		return
	}

	pluginHandle.logger.Info("plugin abort")
}
