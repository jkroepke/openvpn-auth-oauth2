//go:build linux

package main

/*

#include <openvpn-plugin.h>

*/

import "C"

import (
	"context"
	"fmt"
	"log/slog"
	http2 "net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

//goland:noinspection GoSnakeCaseUsage

const OPENVPN_PLUGIN_STRUCTVER_MIN = 5

//export openvpn_plugin_select_initialization_point_v1

//goland:noinspection GoSnakeCaseUsage

func openvpn_plugin_select_initialization_point_v1() C.int {
	return 2
}

//export openvpn_plugin_min_version_required_v1

//goland:noinspection GoSnakeCaseUsage

func openvpn_plugin_min_version_required_v1() C.int {
	return 3
}

//export openvpn_plugin_open_v3_go

//goland:noinspection GoSnakeCaseUsage

func openvpn_plugin_open_v3_go(v3structver C.int, args *C.struct_openvpn_plugin_args_open_in, ret *C.struct_openvpn_plugin_args_open_return) C.int {
	if v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN {
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	ret.type_mask = 1 << C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY

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

	handle := &PluginHandle{
		logger: logger,

		conf: conf,
	}

	ctx := context.Background()

	storageClient := storage.New(ctx, conf.OAuth2.Refresh.Secret.String(), conf.OAuth2.Refresh.Expires)

	provider := oauth2.New(logger, conf, storageClient, http2.DefaultClient)

	if err = provider.Initialize(ctx, handle); err != nil {

		logger.Error(err.Error())

		return C.OPENVPN_PLUGIN_FUNC_ERROR

	}

	handle.server = httpserver.NewHTTPServer("server", logger, conf.HTTP, provider.Handler())

	go func() {
		if err := handle.server.Listen(context.Background()); err != nil {

			logger.Error(fmt.Errorf("error http listener: %w", err).Error())

			os.Exit(1)

		}
	}()

	ret.handle = (C.openvpn_plugin_handle_t)(unsafe.Pointer(handle))

	logger.Info(fmt.Sprintf("plugin initialization done. version: %s", version))

	logger.Warn("THIS PLUGIN IS STILL IN EXPERIMENTAL STATE")

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

//export openvpn_plugin_func_v3_go

//goland:noinspection GoSnakeCaseUsage

func openvpn_plugin_func_v3_go(v3structver C.int, args *C.struct_openvpn_plugin_args_func_in, _ *C.struct_openvpn_plugin_args_func_return) C.int {
	if v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN {
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	handle := (*PluginHandle)(unsafe.Pointer(args.handle))

	if args._type != C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY {

		handle.logger.Error("OPENVPN_PLUGIN_? called")

		return C.OPENVPN_PLUGIN_FUNC_ERROR

	}

	client := NewClient(unsafe.Pointer(args.envp))

	if client.CommonName != "" && slices.Contains(handle.conf.OpenVpn.Bypass.CommonNames, client.CommonName) {

		handle.logger.Info(fmt.Sprintf("client %s bypass authentication", client.CommonName))

		return C.OPENVPN_PLUGIN_FUNC_SUCCESS

	}

	clientIdentifier := state.ClientIdentifier{
		AuthControlFile: client.AuthControlFile,

		AuthFailedReasonFile: client.AuthFailedReasonFile,
	}

	session := state.New(clientIdentifier, client.IpAddr, client.IpPort, client.CommonName)

	encodedSession, err := session.Encode(handle.conf.HTTP.Secret.String())
	if err != nil {

		handle.logger.Error(fmt.Errorf("encoding state: %w", err).Error())

		return C.OPENVPN_PLUGIN_FUNC_ERROR

	}

	startURL := utils.StringConcat(

		strings.TrimSuffix(handle.conf.HTTP.BaseURL.String(), "/"),

		"/oauth2/start?state=", url.QueryEscape(encodedSession),
	)

	pendingAuth := fmt.Sprintf("%.0f\nwebauth\nWEB_AUTH::%s", handle.conf.OpenVpn.AuthPendingTimeout.Seconds(), startURL)

	if err := os.WriteFile(client.AuthPendingFile, []byte(pendingAuth), 0o600); err != nil {

		handle.logger.Error(fmt.Errorf("write to file %s: %w", client.AuthPendingFile, err).Error())

		return C.OPENVPN_PLUGIN_FUNC_ERROR

	}

	return C.OPENVPN_PLUGIN_FUNC_DEFERRED
}

//export openvpn_plugin_close_v1

//goland:noinspection GoSnakeCaseUsage

func openvpn_plugin_close_v1(pluginHandle C.openvpn_plugin_handle_t) {
	handle := (*PluginHandle)(unsafe.Pointer(pluginHandle))

	if handle == nil {
		return
	}

	handle.logger.Info("plugin closed")
}

//export openvpn_plugin_abort_v1

//goland:noinspection GoSnakeCaseUsage

func openvpn_plugin_abort_v1(pluginHandle C.openvpn_plugin_handle_t) {
	handle := (*PluginHandle)(unsafe.Pointer(pluginHandle))

	if handle == nil {
		return
	}

	handle.logger.Info("plugin abort")
}
