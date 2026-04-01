//go:build (linux || openbsd || freebsd) && cgo

package openvpn

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"runtime/cgo"
	"strings"
	"sync/atomic"
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
	PluginTypeMask           = 1<<c.OpenVPNPluginUp |
		1<<c.OpenVPNPluginAuthUserPassVerify |
		1<<c.OpenVPNPluginClientConnectV2 |
		1<<c.OpenVPNPluginClientDisconnect
)

// clientIDCounter is a global counter for client IDs, incremented atomically.
//
//nolint:gochecknoglobals
var clientIDCounter atomic.Uint64

var (
	errMissingPluginHandle     = errors.New("missing plugin handle")
	errInvalidPluginHandle     = errors.New("invalid plugin handle")
	errInvalidPluginHandleType = errors.New("invalid plugin handle type")
)

func PluginOpenV3(v3structver c.Int, args *c.OpenVPNPluginArgsOpenIn, ret *c.OpenVPNPluginArgsOpenReturn) c.Int {
	if v3structver < PluginStructVerMin || args == nil || ret == nil {
		return c.OpenVPNPluginFuncError
	}

	ret.TypeMask = PluginTypeMask

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

	ctx, cancel := context.WithCancel(context.Background())

	handle := c.NewOpenVPNPluginHandle(&PluginHandle{
		logger:           logger,
		managementClient: management.NewServer(logger, listenSocketPassword),
		ctx:              ctx,
		cancel:           cancel,
		listenSocketAddr: listenSocketAddr,
	})

	ret.Handle = handle

	logger.InfoContext(ctx, "plugin loaded",
		slog.String("version", version.Version),
	)

	logger.WarnContext(ctx, "THIS PLUGIN IS STILL IN EXPERIMENTAL STATE")

	return c.OpenVPNPluginFuncSuccess
}

func PluginFuncV3(v3structver c.Int, args *c.OpenVPNPluginArgsFuncIn, ret *c.OpenVPNPluginArgsFuncReturn) c.OpenVPNPluginFuncStatus {
	if v3structver < PluginStructVerMin || args == nil || ret == nil {
		return c.OpenVPNPluginFuncError
	}

	handle, err := pluginHandleFromPtr(args.Handle)
	if err != nil {
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
	// argv: a NULL-terminated array of "command line" options which
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

	switch args.Type {
	case c.OpenVPNPluginUp:
		return handle.handlePluginUp()
	case c.OpenVPNPluginAuthUserPassVerify:
		return handle.handleAuthUserPassVerify(args.Envp, clientContextFromPointer(args.PerClientContext))
	case c.OpenVPNPluginClientConnectV2:
		return handle.handleClientConnect(clientContextFromPointer(args.PerClientContext), ret)
	case c.OpenVPNPluginClientDisconnect:
		return handle.handleClientDisconnect(args.Envp, clientContextFromPointer(args.PerClientContext))
	default:
		handle.logger.ErrorContext(handle.ctx, "unhandled OPENVPN_PLUGIN event",
			slog.Int("event_type", int(args.Type)),
		)

		return c.OpenVPNPluginFuncError
	}
}

func PluginCloseV1(handlePtr c.OpenVPNPluginHandle) {
	handle, err := pluginHandleFromPtr(handlePtr)
	if err != nil {
		return
	}

	handle.cancel()
	handle.managementClient.Close()

	handle.logger.InfoContext(handle.ctx, "plugin closed")

	handlePtr.Delete() // frees handle, allows GC to collect Go object
}

// PluginClientConstructorV1 allocates a new per-client context using cgo.Handle
// so the ClientContext remains fully GC-managed. The returned unsafe.Pointer
// encodes the cgo.Handle value and is opaque to OpenVPN.
func PluginClientConstructorV1(handlePtr c.OpenVPNPluginHandle) unsafe.Pointer {
	handle, err := pluginHandleFromPtr(handlePtr)
	if err != nil {
		return nil
	}

	handle.logger.DebugContext(handle.ctx, "openvpn_plugin_client_constructor_v1: called")

	ctx := &ClientContext{}
	h := cgo.NewHandle(ctx)

	//goland:noinspection GoVetUnsafePointer
	return unsafe.Pointer(uintptr(h)) //nolint:unsafeptr // encoding cgo.Handle as opaque pointer for OpenVPN
}

// PluginClientDestructorV1 frees the per-client cgo.Handle previously returned
// by PluginClientConstructorV1.
func PluginClientDestructorV1(handlePtr c.OpenVPNPluginHandle, perClientContext unsafe.Pointer) {
	handle, err := pluginHandleFromPtr(handlePtr)
	if err != nil {
		return
	}

	handle.logger.DebugContext(handle.ctx, "openvpn_plugin_client_destructor_v1: called")

	if perClientContext == nil {
		return
	}

	cgo.Handle(uintptr(perClientContext)).Delete()
}

func PluginAbortV1(handlePtr c.OpenVPNPluginHandle) {
	if handlePtr.IsNil() {
		return
	}

	handle, err := pluginHandleFromPtr(handlePtr)
	if err != nil {
		return
	}

	handle.cancel()
	handle.managementClient.Close()

	handle.logger.WarnContext(handle.ctx, "plugin abort")

	// frees the handle, allows GC to collect Go object
	handlePtr.Delete()
}

// clientContextFromPointer recovers a *ClientContext from an opaque unsafe.Pointer
// that encodes a cgo.Handle (as returned by PluginClientConstructorV1).
func clientContextFromPointer(ptr unsafe.Pointer) *ClientContext {
	if ptr == nil {
		return nil
	}

	return cgo.Handle(uintptr(ptr)).Value().(*ClientContext)
}

func pluginHandleFromPtr(handlePtr c.OpenVPNPluginHandle) (*PluginHandle, error) {
	if handlePtr.IsNil() {
		return nil, errMissingPluginHandle
	}

	var (
		handleValue any
		recovered   bool
	)

	func() {
		defer func() {
			if recover() != nil {
				recovered = true
			}
		}()

		handleValue = handlePtr.Value()
	}()

	if recovered {
		return nil, errInvalidPluginHandle
	}

	h, ok := handleValue.(*PluginHandle)
	if !ok {
		return nil, errInvalidPluginHandleType
	}

	return h, nil
}
