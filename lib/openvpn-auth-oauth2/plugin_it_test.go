package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/net/nettest"
)

const entrypointScript = `#!/bin/sh
set -e

if [ ! -f /etc/openvpn/pki/ca.crt ]; then
  /usr/share/easy-rsa/easyrsa init-pki nopass
  /usr/share/easy-rsa/easyrsa build-ca nopass
  /usr/share/easy-rsa/easyrsa build-server-full server nopass
  /usr/share/easy-rsa/easyrsa build-client-full ${UPN} nopass
fi

if [ ! -f /etc/openvpn/password.txt ]; then
  printf password > /etc/openvpn/password.txt
fi

if [ ! -d /etc/openvpn/client-config ]; then
  mkdir /etc/openvpn/client-config
fi

cat > "/etc/openvpn/openvpn.conf" <<EOF
dev tun0
server 100.64.0.0 255.255.255.0
verb 3
ca /etc/openvpn/pki/ca.crt
key /etc/openvpn/pki/private/server.key
cert /etc/openvpn/pki/issued/server.crt
dh none
keepalive 10 60
#persist-key
persist-tun
explicit-exit-notify

verify-client-cert none
username-as-common-name
script-security 2

status /etc/openvpn/openvpn-status.log
ifconfig-pool-persist /etc/openvpn/ipp.txt

tls-cert-profile preferred

inactive 65

topology subnet
proto tcp
port 1194

fast-io
user nobody
group nogroup

# Does not work in containers
disable-dco
duplicate-cn

client-config-dir /etc/openvpn/client-config

plugin /plugin/openvpn-auth-oauth2.so tcp://0.0.0.0:8081 /etc/openvpn/password.txt

reneg-sec 600
push "reneg-sec 0"

auth-gen-token 300 external-auth
auth-user-pass-optional

EOF

cat > "/etc/openvpn/${UPN}.ovpn" <<EOF
client
dev tun
setenv "IV_SSO" "webauth"
nobind
remote 127.0.0.1 1194 tcp4
remote-cert-tls server
connect-retry-max 2
tls-cert-profile preferred
persist-tun
verb 3
management 0.0.0.0 8082
management-hold
<key>
$(cat /etc/openvpn/pki/private/${UPN}.key)
</key>
<cert>
$(openssl x509 -in /etc/openvpn/pki/issued/${UPN}.crt)
</cert>
<ca>
$(cat /etc/openvpn/pki/ca.crt)
</ca>
EOF

git -C /build/ log -1
exec openvpn --config "/etc/openvpn/openvpn.conf" --tmp-dir /tmp/
`

func TestIT(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	if os.Getenv("CI") == "" && os.Getenv("PLUGIN_IT_TEST") != "1" {
		t.Skip("Skipping integration test, PLUGIN_IT_TEST not set")
	}

	testcontainers.SkipIfProviderIsNotHealthy(t)

	containerServer, err := testcontainers.Run(t.Context(), "",
		testcontainers.WithName("openvpn-auth-oauth2-it-server"),
		testcontainers.WithDockerfile(testcontainers.FromDockerfile{
			Context:    `../../`,
			Dockerfile: `./tests/Dockerfile`,
			Repo:       "testcontainers/openvpn-auth-oauth2",
			Tag:        "latest",
		}),
		testcontainers.WithExposedPorts("8081/tcp", "8082/tcp"),
		testcontainers.WithWaitStrategy(wait.ForExposedPort().WithPollInterval(1*time.Second)),
		testcontainers.WithLabels(map[string]string{
			"testcontainers": "true",
		}),
		testcontainers.WithEnv(map[string]string{
			"UPN": "user@example.com",
		}),
		testcontainers.WithMounts(testcontainers.ContainerMount{
			Source: testcontainers.GenericVolumeMountSource{Name: "openvpn-auth-oauth2-it-data"},
			Target: "/etc/openvpn",
		}),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			Reader:            strings.NewReader(entrypointScript),
			ContainerFilePath: "/entrypoint.sh",
			FileMode:          0o755,
		}),
		testcontainers.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
			hostConfig.ExtraHosts = []string{"host.docker.internal:host-gateway"}
			hostConfig.Binds = []string{"/dev/net/tun:/dev/net/tun"}
			hostConfig.CapAdd = []string{"NET_ADMIN"}
		}),
		testcontainers.WithEntrypoint("/entrypoint.sh"),
	)

	if containerServer == nil {
		require.NoError(t, err)

		return
	}

	testcontainers.CleanupContainer(t, containerServer)

	containerServerLogs, _ := getContainerLogs(t, containerServer)
	require.NoError(t, err, containerServerLogs)

	containerClient, err := testcontainers.Run(t.Context(), "",
		testcontainers.WithName("openvpn-auth-oauth2-it-client"),
		testcontainers.WithDockerfile(testcontainers.FromDockerfile{
			Context:    `../../`,
			Dockerfile: `./tests/Dockerfile`,
			Repo:       "testcontainers/openvpn-auth-oauth2",
			Tag:        "latest",
		}),
		testcontainers.WithLabels(map[string]string{
			"testcontainers": "true",
		}),
		testcontainers.WithMounts(testcontainers.ContainerMount{
			Source: testcontainers.GenericVolumeMountSource{Name: "openvpn-auth-oauth2-it-data"},
			Target: "/etc/openvpn",
		}),
		testcontainers.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
			hostConfig.Binds = []string{"/dev/net/tun:/dev/net/tun"}
			hostConfig.CapAdd = []string{"NET_ADMIN"}
			hostConfig.NetworkMode = container.NetworkMode("container:" + containerServer.GetContainerID())
		}),
		testcontainers.WithWaitStrategy(wait.ForLog("Need hold release from management interface").WithPollInterval(1*time.Second)),
		testcontainers.WithEntrypoint("openvpn"),
		testcontainers.WithEntrypointArgs("--config", "/etc/openvpn/user@example.com.ovpn", "--echo", "off"),
	)

	if containerClient == nil {
		require.NoError(t, err)

		return
	}

	testcontainers.CleanupContainer(t, containerClient)

	containerClientLogs, _ := getContainerLogs(t, containerClient)
	require.NoError(t, err, containerClientLogs)

	conf := config.Defaults
	conf.HTTP.Secret = testutils.Secret

	logger := testutils.NewTestLogger()

	// clientListener must not be closed, because it is used by the httpClientListener.
	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	_, resourceServerURL, clientCredentials, err := testutils.SetupResourceServer(t, clientListener, logger.Logger, nil)
	require.NoError(t, err)

	pluginManagementEndpoint, err := containerServer.PortEndpoint(t.Context(), "8081", "tcp")
	require.NoError(t, err)

	conf.OAuth2.Issuer = resourceServerURL
	conf.OAuth2.Nonce = true                                  // enable nonce for mock testing
	conf.OAuth2.RefreshNonce = config.OAuth2RefreshNonceEmpty // use empty nonce for refresh to avoid mock issues
	conf.OAuth2.Client.ID = clientCredentials.ID
	conf.OAuth2.Client.Secret = clientCredentials.Secret
	conf.OAuth2.Refresh.Expires = time.Hour
	conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: clientListener.Addr().String()}}
	conf.OpenVPN.Addr = types.URL{URL: &url.URL{Scheme: "tcp", Host: strings.TrimPrefix(pluginManagementEndpoint, "tcp://")}}
	conf.OpenVPN.Password = testutils.Password

	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, conf.OAuth2.Refresh.Expires)
	oAuth2Client, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(t.Context(), t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	errOpenVPNClientCh := make(chan error, 1)

	go func(errCh chan<- error) {
		errCh <- openVPNClient.Connect(t.Context())
	}(errOpenVPNClientCh)

	select {
	case err := <-errOpenVPNClientCh:
		require.NoError(t, err)
	default:
	}

	t.Cleanup(func() {
		openVPNClient.Shutdown(t.Context())
	})

	httpHandler := httphandler.New(conf, oAuth2Client)
	httpClientListener := httptest.NewUnstartedServer(httpHandler)
	require.NoError(t, httpClientListener.Listener.Close())

	httpClientListener.Listener = clientListener
	httpClientListener.Start()
	t.Cleanup(httpClientListener.Close)

	clientManagementEndpoint, err := containerServer.PortEndpoint(t.Context(), "8082", "tcp")
	require.NoError(t, err)

	var dial net.Dialer

	client, err := dial.DialContext(t.Context(), "tcp", strings.TrimPrefix(clientManagementEndpoint, "tcp://"))
	require.NoError(t, err)

	clientReader := bufio.NewReader(client)
	testutils.ExpectMessage(t, client, clientReader, openvpn.WelcomeBanner)
	testutils.ExpectMessage(t, client, clientReader, ">HOLD:Waiting for hold release:0")
	testutils.SendAndExpectMessage(t, client, clientReader, "hold release", "SUCCESS: hold release succeeded")

	err = client.SetReadDeadline(time.Now().Add(time.Second * 4))
	require.NoError(t, err)

	line, err := clientReader.ReadString('\n')
	require.NoError(t, err)

	containerServerLogs, _ = getContainerLogs(t, containerServer)
	containerClientLogs, _ = getContainerLogs(t, containerClient)
	require.Contains(t, line, ">INFOMSG:WEB_AUTH", "server logs:\n%s\nclient logs:\n%s", containerServerLogs, containerClientLogs)

	webauthURL := strings.TrimSpace(strings.TrimPrefix(line, ">INFOMSG:WEB_AUTH::"))

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	httpClientListenerClient := httpClientListener.Client()
	httpClientListenerClient.Jar = jar

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, webauthURL, nil)
	require.NoError(t, err)

	resp, err := httpClientListenerClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	time.Sleep(2 * time.Second)

	err = client.SetReadDeadline(time.Now().Add(time.Second * 4))
	require.NoError(t, err)

	line, err = clientReader.ReadString('\n')
	require.NoError(t, err)

	containerServerLogs, _ = getContainerLogs(t, containerServer)
	containerClientLogs, _ = getContainerLogs(t, containerClient)
	require.Contains(t, line, ">PASSWORD:Auth-Token:", "server logs:\n%s\nclient logs:\n%s", containerServerLogs, containerClientLogs)
}

func getContainerLogs(t *testing.T, ctr testcontainers.Container) (string, error) {
	t.Helper()

	cli, err := testcontainers.NewDockerClientWithOpts(t.Context())
	if err != nil {
		return "", fmt.Errorf("failed to create Docker client: %w", err)
	}

	logReader, err := cli.ContainerLogs(t.Context(), ctr.GetContainerID(), container.LogsOptions{
		ShowStderr: true,
		ShowStdout: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get container logs: %w", err)
	}

	containerLogs, err := io.ReadAll(logReader)
	if err != nil {
		return "", fmt.Errorf("error reading container logs: %w", err)
	}

	return string(containerLogs), nil
}
