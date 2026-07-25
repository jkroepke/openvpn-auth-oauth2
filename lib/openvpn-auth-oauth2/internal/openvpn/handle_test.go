//go:build (darwin || linux || openbsd || freebsd) && cgo

//nolint:testpackage
package openvpn

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/internal/c"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/internal/management"
	"github.com/stretchr/testify/require"
)

func TestHandlePluginUp(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name      string
		listenErr error
		expected  c.OpenVPNPluginFuncStatus
	}{
		{
			name:     "listener started",
			expected: c.OpenVPNPluginFuncSuccess,
		},
		{
			name:      "listener failed",
			listenErr: errors.New("listen failed"),
			expected:  c.OpenVPNPluginFuncError,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			handle := newStubbedPluginHandle(t, &stubManagementServer{listenErr: testCase.listenErr}, nil)

			require.Equal(t, testCase.expected, handle.handlePluginUp())
		})
	}
}

//nolint:paralleltest // handleAuthUserPassVerify increments the package-level clientIDCounter.
func TestHandleAuthUserPassVerifyFinalResponses(t *testing.T) {
	for _, testCase := range []struct {
		name                   string
		response               *management.Response
		authFailedReasonTarget func(t *testing.T) string
		expectedStatus         c.OpenVPNPluginFuncStatus
		expectedClientConfig   string
		expectedFailedReason   string
		expectedLog            string
	}{
		{
			name: "accepted",
			response: &management.Response{
				ClientAuth:   management.ClientAuthAccept,
				ClientConfig: "push \"auth-token-user aWQx\"",
			},
			expectedStatus:       c.OpenVPNPluginFuncSuccess,
			expectedClientConfig: "push \"auth-token-user aWQx\"",
		},
		{
			name: "denied with default reason",
			response: &management.Response{
				ClientAuth: management.ClientAuthDeny,
			},
			authFailedReasonTarget: func(t *testing.T) string {
				t.Helper()

				return t.TempDir() + "/auth-failed-reason"
			},
			expectedStatus:       c.OpenVPNPluginFuncError,
			expectedFailedReason: "authentication failed",
		},
		{
			name: "failed reason cannot be written",
			response: &management.Response{
				ClientAuth: management.ClientAuthDeny,
				Message:    "access denied",
			},
			authFailedReasonTarget: func(t *testing.T) string {
				t.Helper()

				return t.TempDir()
			},
			expectedStatus: c.OpenVPNPluginFuncError,
			expectedLog:    "write to failed reason file",
		},
		{
			name: "unknown response",
			response: &management.Response{
				ClientAuth: management.ClientAuth(99),
			},
			expectedStatus: c.OpenVPNPluginFuncError,
			expectedLog:    "unknown client auth response",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			managementClient := &stubManagementServer{clientAuthResponse: testCase.response}
			handle := newStubbedPluginHandle(t, managementClient, logs)
			clientContext := &ClientContext{}
			env := validAuthUserPassVerifyEnv()

			var authFailedReasonFile string
			if testCase.authFailedReasonTarget != nil {
				authFailedReasonFile = testCase.authFailedReasonTarget(t)
				env = append(env, "auth_failed_reason_file="+authFailedReasonFile)
			}

			status := handle.handleAuthUserPassVerify(newTestEnvp(t, env), clientContext)

			require.Equal(t, testCase.expectedStatus, status)
			require.Equal(t, testCase.expectedClientConfig, clientContext.clientConfig)

			if testCase.expectedFailedReason != "" {
				data, err := os.ReadFile(authFailedReasonFile)
				require.NoError(t, err)
				require.Equal(t, testCase.expectedFailedReason, string(data))
			}

			if testCase.expectedLog != "" {
				require.Contains(t, logs.String(), testCase.expectedLog)
			}
		})
	}
}

//nolint:paralleltest // handleAuthUserPassVerify increments the package-level clientIDCounter.
func TestHandleAuthUserPassVerifyPendingSetupErrors(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		registerErr     error
		expectCancelled bool
	}{
		{
			name:        "poller registration failed",
			registerErr: errors.New("registration failed"),
		},
		{
			name:            "pending file missing",
			expectCancelled: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			managementClient := &stubManagementServer{
				clientAuthResponse: pendingAuthResponse(),
				registerPendingErr: testCase.registerErr,
			}
			handle := newStubbedPluginHandle(t, managementClient, nil)
			env := validAuthUserPassVerifyEnv()

			status := handle.handleAuthUserPassVerify(newTestEnvp(t, env), &ClientContext{})

			require.Equal(t, c.OpenVPNPluginFuncError, status)
			require.Equal(t, testCase.expectCancelled, managementClient.pendingCancelled)
		})
	}
}

//nolint:paralleltest // handleAuthUserPassVerify increments the package-level clientIDCounter.
func TestHandleAuthUserPassVerifyDeferredResponses(t *testing.T) {
	for _, testCase := range []struct {
		name                 string
		response             *management.Response
		waitErr              error
		includeControlFile   bool
		expectedControlValue string
		expectedClientConfig string
		expectedFailedReason string
		expectedLog          string
	}{
		{
			name: "accepted",
			response: &management.Response{
				ClientAuth:   management.ClientAuthAccept,
				ClientConfig: "push \"auth-token-user aWQx\"",
			},
			includeControlFile:   true,
			expectedControlValue: "1",
			expectedClientConfig: "push \"auth-token-user aWQx\"",
		},
		{
			name: "accepted without auth control file",
			response: &management.Response{
				ClientAuth:   management.ClientAuthAccept,
				ClientConfig: "push \"auth-token-user aWQx\"",
			},
			expectedClientConfig: "push \"auth-token-user aWQx\"",
			expectedLog:          "write to auth file",
		},
		{
			name: "denied",
			response: &management.Response{
				ClientAuth: management.ClientAuthDeny,
				Message:    "access denied",
			},
			includeControlFile:   true,
			expectedControlValue: "0",
			expectedFailedReason: "access denied",
		},
		{
			name: "denied without auth control file",
			response: &management.Response{
				ClientAuth: management.ClientAuthDeny,
				Message:    "access denied",
			},
			expectedFailedReason: "access denied",
			expectedLog:          "write to auth file",
		},
		{
			name:        "wait failed",
			waitErr:     errors.New("wait failed"),
			expectedLog: "poll deferred auth state",
		},
		{
			name: "unknown response",
			response: &management.Response{
				ClientAuth: management.ClientAuth(99),
			},
			expectedLog: "unknown auth state",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			managementClient := &stubManagementServer{
				clientAuthResponse:  pendingAuthResponse(),
				waitPendingResponse: testCase.response,
				waitPendingErr:      testCase.waitErr,
			}
			handle := newStubbedPluginHandle(t, managementClient, logs)
			clientContext := &ClientContext{}
			tempDir := t.TempDir()
			authControlFile := tempDir + "/auth-control"
			authFailedReasonFile := tempDir + "/auth-failed-reason"
			env := append(
				validAuthUserPassVerifyEnv(),
				"auth_pending_file="+tempDir+"/auth-pending",
				"auth_failed_reason_file="+authFailedReasonFile,
			)

			if testCase.includeControlFile {
				env = append(env, "auth_control_file="+authControlFile)
			}

			status := handle.handleAuthUserPassVerify(newTestEnvp(t, env), clientContext)

			require.Equal(t, c.OpenVPNPluginFuncDeferred, status)

			require.Eventually(t, func() bool {
				if testCase.expectedControlValue != "" {
					data, err := os.ReadFile(authControlFile)
					if err != nil || string(data) != testCase.expectedControlValue {
						return false
					}
				}

				if testCase.expectedClientConfig != "" {
					clientContext.mu.Lock()
					clientConfig := clientContext.clientConfig
					clientContext.mu.Unlock()

					if clientConfig != testCase.expectedClientConfig {
						return false
					}
				}

				if testCase.expectedFailedReason != "" {
					data, err := os.ReadFile(authFailedReasonFile)
					if err != nil || string(data) != testCase.expectedFailedReason {
						return false
					}
				}

				return testCase.expectedLog == "" || bytes.Contains(logs.Bytes(), []byte(testCase.expectedLog))
			}, time.Second, 10*time.Millisecond)
		})
	}
}

func pendingAuthResponse() *management.Response {
	return &management.Response{
		ClientAuth: management.ClientAuthPending,
		Message:    "WEB_AUTH::https://example.com",
		Timeout:    "300",
	}
}

func newStubbedPluginHandle(t *testing.T, managementClient managementServer, logs *lockedBuffer) *PluginHandle {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	logger := slog.New(slog.DiscardHandler)
	if logs != nil {
		logger = slog.New(slog.NewTextHandler(logs, nil))
	}

	return &PluginHandle{
		ctx:              ctx,
		cancel:           cancel,
		logger:           logger,
		managementClient: managementClient,
		listenSocketAddr: "tcp://127.0.0.1:0",
	}
}

type stubManagementServer struct {
	clientAuthResponse  *management.Response
	waitPendingResponse *management.Response
	clientAuthErr       error
	listenErr           error
	registerPendingErr  error
	waitPendingErr      error
	disconnectErr       error
	pendingCancelled    bool
}

func (s *stubManagementServer) Listen(context.Context, string) error {
	return s.listenErr
}

func (s *stubManagementServer) Close() {}

func (s *stubManagementServer) ClientAuth(context.Context, uint64, string) (*management.Response, error) {
	return s.clientAuthResponse, s.clientAuthErr
}

func (s *stubManagementServer) ClientDisconnect(string) error {
	return s.disconnectErr
}

func (s *stubManagementServer) RegisterPendingPoller(uint64) (chan *management.Response, error) {
	if s.registerPendingErr != nil {
		return nil, s.registerPendingErr
	}

	return make(chan *management.Response), nil
}

func (s *stubManagementServer) WaitPendingPoller(
	context.Context,
	uint64,
	time.Duration,
	<-chan *management.Response,
) (*management.Response, error) {
	return s.waitPendingResponse, s.waitPendingErr
}

func (s *stubManagementServer) CancelPendingPoller(uint64) {
	s.pendingCancelled = true
}

type lockedBuffer struct {
	buffer bytes.Buffer
	mu     sync.Mutex
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.Write(data)
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	return bytes.Clone(b.buffer.Bytes())
}

func (b *lockedBuffer) String() string {
	return string(b.Bytes())
}
