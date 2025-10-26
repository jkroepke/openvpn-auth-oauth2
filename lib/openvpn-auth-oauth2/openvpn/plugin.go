package openvpn

import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime/cgo"
	"strings"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/version"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/log"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util"
)

const (
	PluginStructVerMin c.Int = 5
	PluginVerMin       c.Int = 3
)

// clientIDCounter is a global counter for client IDs, incremented atomically.
//
//nolint:gochecknoglobals
var clientIDCounter uint64

func PluginOpenV3(v3structver c.Int, args *c.OpenVPNPluginArgsOpenIn, ret *c.OpenVPNPluginArgsOpenReturn) c.Int {
	if v3structver < PluginStructVerMin {
		return c.OpenVPNPluginFuncError
	}

	ret.TypeMask = 1<<c.OpenVPNPluginUp |
		1<<c.OpenVPNPluginAuthUserPassVerify |
		1<<c.OpenVPNPluginClientConnectV2 |
		1<<c.OpenVPNPluginClientDisconnect

	pluginArgs := util.ArgvToStrings(args.Argv)

	logger := slog.New(log.NewOpenVPNPluginLogger(args.Callbacks))

	if len(pluginArgs) > 3 || len(pluginArgs) < 2 {
		logger.Error("Invalid amount of arguments! openvpn-auth-oauth2.so <listen socket> [<password-file>]")

		return c.OpenVPNPluginFuncError
	}

	listenSocketAddr := pluginArgs[1]

	var listenSocketPassword string

	if len(pluginArgs) == 3 {
		password, err := os.ReadFile(pluginArgs[2])
		if err != nil {
			logger.Error("Failed to read password file",
				slog.Any("err", err),
			)

			return c.OpenVPNPluginFuncError
		}

		listenSocketPassword = strings.TrimSpace(string(password))
	}

	ctx := context.Background()

	handle := cgo.NewHandle(&pluginHandle{
		logger:           logger,
		managementClient: management.NewServer(logger, listenSocketPassword),
		ctx:              ctx,
		listenSocketAddr: listenSocketAddr,
	})

	ret.Handle = &handle

	logger.InfoContext(ctx, "plugin loaded",
		slog.String("version", version.Version),
	)

	logger.WarnContext(ctx, "THIS PLUGIN IS STILL IN EXPERIMENTAL STATE")

	return c.OpenVPNPluginFuncSuccess
}

func PluginFuncV3(v3structver c.Int, args *c.OpenVPNPluginArgsFuncIn, ret *c.OpenVPNPluginArgsFuncReturn) c.OpenVPNPluginFuncStatus {
	if v3structver < PluginStructVerMin {
		return c.OpenVPNPluginFuncError
	}

	// args
	// Arguments used to transport variables to and from the
	// plug-in. The struct openvpn_plugin_args_func is only used
	// by the openvpn_plugin_func_v3() function.
	//
	// STRUCT MEMBERS:
	//
	// type: one of the PLUGIN_x types.
	//
	// argv: a NULL-terminated array of “command line” options which
	//        would normally be passed to the script.  argv[0] is the dynamic
	//        library pathname.
	//
	// envp: a NULL-terminated array of OpenVPN-set environmental
	//        variables in "name=value" format. Note that for security reasons,
	//        these variables are not written to the "official"
	//        environmental variable store of the process.
	//
	// handle: Pointer to a global plug-in context, created by the plug-in's openvpn_plugin_open_v3().
	//
	// per_client_context: the per-client context pointer, which was returned by
	//        openvpn_plugin_client_constructor_v1, if defined.

	handle, ok := args.Handle.Value().(*pluginHandle)
	if !ok {
		panic("getPluginHandleFromPtr: invalid plugin handle type")
	}

	if args.Type == c.OpenVPNPluginUp {
		return handle.handlePluginUp()
	}

	perClientContext, ok := cgo.Handle(args.PerClientContext).Value().(*clientContext)
	if !ok {
		handle.logger.ErrorContext(handle.ctx, "invalid per_client_context type")

		return c.OpenVPNPluginFuncError
	}

	switch args.Type {
	case c.OpenVPNPluginAuthUserPassVerify:
		return handle.handleAuthUserPassVerify(args.Envp, perClientContext)
	case c.OpenVPNPluginClientConnectV2:
		return handle.handleClientConnect(perClientContext, ret)
	case c.OpenVPNPluginClientDisconnect:
		return handle.handleClientDisconnect(args.Envp, perClientContext)
	default:
		handle.logger.ErrorContext(handle.ctx, fmt.Sprintf("unhandled OPENVPN_PLUGIN event: %v", args.Type))

		return c.OpenVPNPluginFuncError
	}
}

func PluginCloseV1(handlePtr c.OpenVPNPluginHandle) {
	handle, ok := handlePtr.Value().(*pluginHandle)
	if !ok {
		panic("getPluginHandleFromPtr: invalid plugin handle type")
	}

	handle.managementClient.Close()

	handle.logger.InfoContext(handle.ctx, "plugin closed")

	handlePtr.Delete() // frees handle, allows GC to collect Go object
}

func PluginClientConstructorV1(handlePtr c.OpenVPNPluginHandle) c.OpenVPNPluginClientContext {
	handle, ok := handlePtr.Value().(*pluginHandle)
	if !ok {
		panic("getPluginHandleFromPtr: invalid plugin handle type")
	}

	handle.logger.DebugContext(handle.ctx, "openvpn_plugin_client_constructor_v1: called")

	clientHandle := cgo.NewHandle(&clientContext{})

	//goland:noinspection GoVetUnsafePointer
	return unsafe.Pointer(clientHandle)
}

func PluginClientDestructorV1(handlePtr c.OpenVPNPluginHandle, perClientContext c.OpenVPNPluginClientContext) {
	handle, ok := handlePtr.Value().(*pluginHandle)
	if !ok {
		panic("getPluginHandleFromPtr: invalid plugin handle type")
	}

	handle.logger.DebugContext(handle.ctx, "openvpn_plugin_client_destructor_v1: called")

	cgo.Handle(perClientContext).Delete() // frees handle, allows GC to collect Go object
}

func PluginAbortV1(handlePtr c.OpenVPNPluginHandle) {
	if handlePtr == nil {
		return
	}

	handle, ok := handlePtr.Value().(*pluginHandle)
	if !ok {
		panic("getPluginHandleFromPtr: invalid plugin handle type")
	}

	handle.managementClient.Close()

	handle.logger.WarnContext(handle.ctx, "plugin abort")

	// frees the handle, allows GC to collect Go object
	handlePtr.Delete()
}
