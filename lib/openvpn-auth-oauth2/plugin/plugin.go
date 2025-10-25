package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime/cgo"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/version"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/client"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/log"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util"
)

const (
	OpenVPNPluginStructVerMin c.Int = 5
	OpenVPNPluginVerMin       c.Int = 3
)

// clientIDCounter is a global counter for client IDs, incremented atomically.
//
//nolint:gochecknoglobals
var clientIDCounter uint64

// openvpn_plugin_select_initialization_point_v1
//
// Several points exist in OpenVPNs initialization sequence where
// the openvpn_plugin_open function can be called. While the default is
// OPENVPN_PLUGIN_INIT_PRE_DAEMON, this function can be used to select a
// different initialization point. For example, if the plugin needs to
// return configuration parameters to OpenVPN, use
// OPENVPN_PLUGIN_INIT_PRE_CONFIG_PARSE.
//
//export openvpn_plugin_select_initialization_point_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_select_initialization_point_v1() c.Int {
	return c.OpenVPNPluginInitPreDaemon
}

// openvpn_plugin_min_version_required_v1
// This function is called by OpenVPN to query the minimum
// plugin interface version number required by the plugin.
//
//export openvpn_plugin_min_version_required_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_min_version_required_v1() c.Int {
	return OpenVPNPluginVerMin
}

// OpenVPNPluginOpenV3 is called by OpenVPN when the plugin is loaded.
// It initializes the plugin, sets up the management interface, and registers
// the plugin event types that this plugin will handle.
//
// Parameters:
//   - v3structver: The OpenVPN plugin API structure version
//   - args: Plugin initialization arguments including argv and callbacks
//   - ret: Return structure where the plugin sets the type_mask and handle
//
// Returns:
//   - c.OpenVPNPluginFuncSuccess on successful initialization
//   - c.OpenVPNPluginFuncError on failure
//
// The function expects plugin arguments in the format:
//
//	openvpn-auth-oauth2.so <listen socket> [<password-file>]
//
//export openvpn_plugin_open_v3_go
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_open_v3_go(v3structver c.Int, args *c.OpenVPNPluginArgsOpenIn, ret *c.OpenVPNPluginArgsOpenReturn) c.Int {
	if v3structver < OpenVPNPluginStructVerMin {
		return c.OpenVPNPluginFuncError
	}

	c.SetTypeMask(ret,
		1<<c.OpenVPNPluginUp|
			1<<c.OpenVPNPluginAuthUserPassVerify|
			1<<c.OpenVPNPluginClientConnectV2|
			1<<c.OpenVPNPluginClientConnectDeferV2|
			1<<c.OpenVPNPluginClientDisconnect,
	)

	pluginArgs := util.ArgvToStrings(c.GetArgs(args))

	logger := slog.New(log.NewOpenVPNPluginLogger(c.GetCallbacks(args)))

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

	c.SetHandle(ret, (c.OpenVPNPluginHandle)(unsafe.Pointer(&handle)))

	logger.InfoContext(ctx, "plugin loaded",
		slog.String("version", version.Version),
	)

	logger.WarnContext(ctx, "THIS PLUGIN IS STILL IN EXPERIMENTAL STATE")

	return c.OpenVPNPluginFuncSuccess
}

// openvpn_plugin_func_v3_go is the main plugin callback function called by OpenVPN
// when plugin events occur. It routes events to the appropriate handler based on
// the event type.
//
//export openvpn_plugin_func_v3_go
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_func_v3_go(v3structver c.Int, args *c.OpenVPNPluginArgsFuncIn, ret *c.OpenVPNPluginArgsFuncReturn) c.OpenVPNPluginFuncStatus {
	if v3structver < OpenVPNPluginStructVerMin {
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

	handle := getPluginHandleFromPtr(c.GetHandle(args))
	fnType := c.GetType(args)

	if fnType == c.OpenVPNPluginUp {
		return handle.handlePluginUp()
	}

	perClientContext, ok := cgo.Handle(c.GetPerClientContext(args)).Value().(*clientContext)
	if !ok {
		handle.logger.ErrorContext(handle.ctx, "invalid per_client_context type")

		return c.OpenVPNPluginFuncError
	}

	switch fnType {
	case c.OpenVPNPluginAuthUserPassVerify:
		return handle.handleAuthUserPassVerify(c.GetEnvp(args), perClientContext)
	case c.OpenVPNPluginClientConnectV2:
		return handle.handleClientConnect(perClientContext, ret)
	case c.OpenVPNPluginClientConnectDeferV2:
		return handle.handleClientConnectDefer(perClientContext, ret)
	case c.OpenVPNPluginClientDisconnect:
		return handle.handleClientDisconnect(c.GetEnvp(args), perClientContext)
	default:
		handle.logger.ErrorContext(handle.ctx, fmt.Sprintf("unhandled OPENVPN_PLUGIN event: %v", fnType))

		return c.OpenVPNPluginFuncError
	}
}

// handlePluginUp handles the OPENVPN_PLUGIN_UP event, which is triggered after
// OpenVPN has completed its initialization and the daemon is ready.
// This function starts the management interface listener.
//
// Returns:
//   - c.OpenVPNPluginFuncSuccess if the listener starts successfully
//   - c.OpenVPNPluginFuncError if the listener fails to start
func (p *pluginHandle) handlePluginUp() c.OpenVPNPluginFuncStatus {
	if err := p.managementClient.Listen(p.ctx, p.listenSocketAddr); err != nil {
		p.logger.ErrorContext(p.ctx, "failed to start management client",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	p.logger.InfoContext(p.ctx, "listener started",
		slog.Any("addr", p.listenSocketAddr),
	)

	return c.OpenVPNPluginFuncSuccess
}

// handleAuthUserPassVerify handles the OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY event,
// which is triggered when a client attempts to authenticate.
//
// This function:
//  1. Parses client environment variables from OpenVPN
//  2. Creates a client context with session information
//  3. Sends authentication request to the management interface
//  4. Handles the authentication response (accept, deny, or pending)
//  5. For pending auth, starts a background poller to wait for completion
//
// Parameters:
//   - clientEnvList: Unsafe pointer to OpenVPN environment variables
//   - perClientContext: Per-client context for storing authentication state
//
// Returns:
//   - c.OpenVPNPluginFuncSuccess if authentication succeeds immediately
//   - c.OpenVPNPluginFuncError if authentication fails or an error occurs
//   - C.OPENVPN_PLUGIN_FUNC_DEFERRED if authentication is pending (OAuth2 flow in progress)
//
//nolint:cyclop
func (p *pluginHandle) handleAuthUserPassVerify(clientEnvList **c.Char, perClientContext *clientContext) c.OpenVPNPluginFuncStatus {
	envArray, err := util.NewEnvList(clientEnvList)
	if err != nil {
		p.logger.ErrorContext(p.ctx, "parse env vars",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	sessionID, ok := envArray["session_id"]
	if !ok {
		p.logger.ErrorContext(p.ctx, "missing session_id in env vars")

		return c.OpenVPNPluginFuncError
	}

	currentClientID := atomic.AddUint64(&clientIDCounter, 1)

	logger := p.logger.With(
		slog.Uint64("client_id", currentClientID),
		slog.String("session_id", sessionID),
		slog.String("client_ip", fmt.Sprintf("%s:%s", envArray["untrusted_ip"], envArray["untrusted_port"])),
	)

	logger.DebugContext(p.ctx, "env", slog.Any("env", envArray))

	openVPNClient, err := client.NewClient(currentClientID, envArray)
	if err != nil {
		logger.ErrorContext(p.ctx, "create OpenVPN client from env vars",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	resp, err := p.managementClient.ClientAuth(currentClientID, openVPNClient.GetConnectMessage())
	if err != nil {
		logger.ErrorContext(p.ctx, "send client to management interface",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	perClientContext.mu.Lock()
	perClientContext.clientID = currentClientID
	perClientContext.authState = resp.ClientAuth
	perClientContext.mu.Unlock()

	logger.InfoContext(p.ctx, "client auth response: "+resp.ClientAuth.String())

	switch resp.ClientAuth {
	case management.ClientAuthAccept:
		if err := openVPNClient.WriteToAuthFile("1"); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)

			return c.OpenVPNPluginFuncError
		}

		perClientContext.mu.Lock()
		perClientContext.clientConfig = resp.ClientConfig
		perClientContext.mu.Unlock()

		return c.OpenVPNPluginFuncSuccess
	case management.ClientAuthDeny:
		reason := "authentication failed"
		if resp.Message != "" {
			reason = resp.Message
		}

		if err := openVPNClient.WriteToAuthFile("0\n" + reason); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)
		}

		return c.OpenVPNPluginFuncError
	case management.ClientAuthPending:
		// Write "2" to auth control file to indicate deferred auth
		if err := openVPNClient.WriteAuthPending(resp); err != nil {
			logger.ErrorContext(p.ctx, "write to auth file",
				slog.Any("err", err),
			)

			return c.OpenVPNPluginFuncError
		}

		go func() {
			resp, err := p.managementClient.AuthPendingPoller(currentClientID, 5*time.Minute)
			if err != nil {
				logger.ErrorContext(p.ctx, "poll deferred auth state",
					slog.Any("err", err),
				)

				return
			}

			if perClientContext != nil {
				perClientContext.mu.Lock()
				perClientContext.authState = resp.ClientAuth
				perClientContext.clientConfig = resp.ClientConfig
				perClientContext.mu.Unlock()
			}
		}()

		return c.OpenVPNPluginFuncDeferred
	default:
		p.logger.ErrorContext(p.ctx, "unknown client auth response from management interface")

		return c.OpenVPNPluginFuncError
	}
}

// handleClientConnect handles the OPENVPN_PLUGIN_CLIENT_CONNECT_V2 event,
// which is triggered when a client attempts to establish a connection after authentication.
//
// This function checks the authentication state and:
//   - Returns DEFERRED if authentication is still pending
//   - Returns SUCCESS and optionally provides client-specific configuration if authenticated
//   - Returns ERROR if authentication was denied or state is invalid
//
// Parameters:
//   - perClientContext: Per-client context containing authentication state and config
//   - ret: Return structure where client-specific configuration can be set
//
// Returns:
//   - c.OpenVPNPluginFuncSuccess if client is authenticated and can connect
//   - c.OpenVPNPluginFuncError if authentication failed or context is invalid
//   - C.OPENVPN_PLUGIN_FUNC_DEFERRED if authentication is still pending
func (p *pluginHandle) handleClientConnect(perClientContext *clientContext, ret *c.OpenVPNPluginArgsFuncReturn) c.OpenVPNPluginFuncStatus {
	if perClientContext == nil {
		p.logger.ErrorContext(p.ctx, "CLIENT_CONNECT_V2: missing perClientContext")

		return c.OpenVPNPluginFuncError
	}

	perClientContext.mu.Lock()
	defer perClientContext.mu.Unlock()

	switch perClientContext.authState {
	case management.ClientAuthPending:
		return c.OpenVPNPluginFuncDeferred
	case management.ClientAuthAccept:
		if perClientContext.clientConfig != "" {
			if ret == nil || c.GetReturnList(ret) == nil {
				p.logger.ErrorContext(p.ctx, "CLIENT_CONNECT_V2: missing return_list")

				return c.OpenVPNPluginFuncError
			}

			returnList := c.CreateStringList()
			if returnList == nil {
				p.logger.ErrorContext(p.ctx, "malloc(return_list) failed")

				return c.OpenVPNPluginFuncError
			}

			c.SetStringListName(returnList, "config")
			c.SetStringListValue(returnList, perClientContext.clientConfig)
			c.SetReturnList(ret, returnList)
		}

		return c.OpenVPNPluginFuncSuccess
	case management.ClientAuthDeny:
		return c.OpenVPNPluginFuncError
	default:
		p.logger.ErrorContext(p.ctx, "CLIENT_CONNECT_V2: unexpected auth state",
			slog.Any("state", perClientContext.authState),
		)

		return c.OpenVPNPluginFuncError
	}
}

// handleClientConnectDefer handles the OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2 event,
// which is triggered when a deferred client connection needs to be completed.
//
// This function delegates to handleClientConnect as the logic is identical.
func (p *pluginHandle) handleClientConnectDefer(perClientContext *clientContext, ret *c.OpenVPNPluginArgsFuncReturn) c.OpenVPNPluginFuncStatus {
	return p.handleClientConnect(perClientContext, ret)
}

func (p *pluginHandle) handleClientDisconnect(clientEnvList **c.Char, perClientContext *clientContext) c.OpenVPNPluginFuncStatus {
	perClientContext.mu.Lock()
	defer perClientContext.mu.Unlock()

	envArray, err := util.NewEnvList(clientEnvList)
	if err != nil {
		p.logger.ErrorContext(p.ctx, "parse env vars",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	openVPNClient, err := client.NewClient(perClientContext.clientID, envArray)
	if err != nil {
		p.logger.ErrorContext(p.ctx, "create OpenVPN client from env vars",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	err = p.managementClient.ClientDisconnect(openVPNClient.GetDisconnectMessage())
	if err != nil {
		p.logger.ErrorContext(p.ctx, "send client to management interface",
			slog.Any("err", err),
		)

		return c.OpenVPNPluginFuncError
	}

	return c.OpenVPNPluginFuncSuccess
}

// openvpn_plugin_close_v1 is called by OpenVPN when the plugin is being unloaded.
// It performs cleanup operations including closing the management client connection
// and freeing the plugin handle.
//
// Parameters:
//   - handlePtr: Pointer to the global plugin context handle
//
//export openvpn_plugin_close_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_close_v1(handlePtr c.OpenVPNPluginHandle) {
	handle := getPluginHandleFromPtr(handlePtr)
	handle.managementClient.Close()

	handle.logger.InfoContext(handle.ctx, "plugin closed")

	(*(*cgo.Handle)(handlePtr)).Delete() // frees handle, allows GC to collect Go object
}

// openvpn_plugin_client_constructor_v1 is called by OpenVPN when a new client connects.
// It creates and returns a per-client context that will be passed to subsequent plugin
// callbacks for this specific client.
//
// The per-client context stores authentication state and client-specific configuration
// that persists throughout the client's connection lifecycle.
//
// Parameters:
//   - handlePtr: Pointer to the global plugin context handle
//
// Returns:
//   - unsafe.Pointer containing a cgo.Handle to the new clientContext
//
//export openvpn_plugin_client_constructor_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_client_constructor_v1(handlePtr c.OpenVPNPluginHandle) unsafe.Pointer {
	handle := getPluginHandleFromPtr(handlePtr)
	handle.logger.DebugContext(handle.ctx, "openvpn_plugin_client_constructor_v1: called")

	clientHandle := cgo.NewHandle(&clientContext{})

	//goland:noinspection GoVetUnsafePointer
	return unsafe.Pointer(clientHandle)
}

// openvpn_plugin_client_destructor_v1 is called by OpenVPN when a client disconnects.
// It performs cleanup operations for the per-client context, freeing the cgo.Handle
// and allowing the Go garbage collector to reclaim the clientContext memory.
//
// Parameters:
//   - handlePtr: Pointer to the global plugin context handle
//   - perClientContext: The per-client context handle to be destroyed
//
//export openvpn_plugin_client_destructor_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_client_destructor_v1(handlePtr c.OpenVPNPluginHandle, perClientContext unsafe.Pointer) {
	handle := getPluginHandleFromPtr(handlePtr)
	handle.logger.DebugContext(handle.ctx, "openvpn_plugin_client_destructor_v1: called")

	cgo.Handle(perClientContext).Delete() // frees handle, allows GC to collect Go object
}

// openvpn_plugin_abort_v1 is called by OpenVPN when an abort signal is received or
// when OpenVPN needs to terminate unexpectedly. It performs emergency cleanup operations
// including closing the management client and freeing the plugin handle.
//
// Parameters:
//   - handlePtr: Pointer to the global plugin context handle
//
//export openvpn_plugin_abort_v1
//nolint:unsed
//goland:noinspection GoSnakeCaseUsage,GoUnusedFunction
func openvpn_plugin_abort_v1(handlePtr c.OpenVPNPluginHandle) {
	handle := getPluginHandleFromPtr(handlePtr)
	handle.managementClient.Close()

	// frees the handle, allows GC to collect Go object
	(*(*cgo.Handle)(handlePtr)).Delete()

	handle.logger.WarnContext(handle.ctx, "plugin abort")
}

func getPluginHandleFromPtr(handlePtr c.OpenVPNPluginHandle) *pluginHandle {
	handle, ok := (*(*cgo.Handle)(handlePtr)).Value().(*pluginHandle)
	if !ok {
		panic("getPluginHandleFromPtr: invalid plugin handle type")
	}

	return handle
}
