package daemon_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/cmd/daemon"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/madflojo/testcerts"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestFull(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		conf config.Config
	}{
		{
			"http",
			config.Defaults,
		},
		{
			"https",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.TLS = true

				return conf
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			httpListener, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)
			require.NoError(t, httpListener.Close())

			resourceServer, _, clientCredentials, err := testutils.SetupResourceServer(t, httpListener, nil, nil)
			require.NoError(t, err)

			buf := new(testutils.SyncBuffer)

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)

			var cert, key string

			httpTransport := &http.Transport{}
			protocol := "http"

			if tc.conf.HTTP.TLS {
				protocol = "https"

				certificateAuthority := testcerts.NewCA()

				keyPair, err := certificateAuthority.NewKeyPair()
				require.NoError(t, err)

				certFile, keyFile, err := keyPair.ToTempFile(t.TempDir())
				require.NoError(t, err)

				cert = certFile.Name()
				key = keyFile.Name()

				httpTransport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: certificateAuthority.CertPool()}
			}

			httpClient := &http.Client{Transport: utils.NewUserAgentTransport(httpTransport)}
			httpClient.Jar = jar

			returnCodeCh := make(chan int, 1)

			termCh := make(chan os.Signal, 1)

			go func() {
				args := []string{
					"openvpn-auth-oauth2",
					"--log.level=debug",
					"--debug.pprof",
					"--debug.listen=127.0.0.1:0",
					fmt.Sprintf("--http.baseurl=%s://%s", protocol, httpListener.Addr().String()),
					"--http.secret=" + testutils.Secret,
					"--http.listen=" + httpListener.Addr().String(),
					"--http.assets-path=../../internal/ui/assets",
					"--openvpn.addr=tcp://" + managementInterface.Addr().String(),
					"--oauth2.issuer", resourceServer.URL,
					"--oauth2.client.id", clientCredentials.ID,
					"--oauth2.client.secret", clientCredentials.Secret.String(),
				}

				if tc.conf.HTTP.TLS {
					args = append(args, "--http.tls=true", "--http.cert="+cert, "--http.key="+key)
				}

				returnCodeCh <- daemon.Execute(args, buf, termCh)
			}()

			t.Cleanup(func() {
				termCh <- syscall.SIGTERM

				require.Equal(t, daemon.ReturnCodeOK, <-returnCodeCh, buf.String())
			})

			managementInterfaceConn, err := managementInterface.Accept()
			require.NoError(t, err)

			defer func() {
				_ = managementInterfaceConn.Close()
			}()

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

			_, err = testutils.WaitUntilListening(t, httpListener.Addr().Network(), httpListener.Addr().String())
			require.NoError(t, err, buf.String())

			msg := strings.Join([]string{
				">CLIENT:CONNECT,0,1",
				">CLIENT:ENV,n_clients=0",
				">CLIENT:ENV,password=",
				">CLIENT:ENV,untrusted_port=17016",
				">CLIENT:ENV,untrusted_ip=192.168.65.1",
				">CLIENT:ENV,common_name=user@example.com",
				">CLIENT:ENV,username=",
				">CLIENT:ENV,IV_BS64DL=1",
				">CLIENT:ENV,IV_SSO=webauth,openurl,crtext",
				">CLIENT:ENV,IV_GUI_VER=OCmacOS_3.4.4-4629",
				">CLIENT:ENV,IV_AUTO_SESS=1",
				">CLIENT:ENV,IV_CIPHERS=AES-128-GCM:AES-192-GCM:AES-256-GCM:CHACHA20-POLY1305",
				">CLIENT:ENV,IV_MTU=1600",
				">CLIENT:ENV,IV_PROTO=990",
				">CLIENT:ENV,IV_TCPNL=1",
				">CLIENT:ENV,IV_NCP=2",
				">CLIENT:ENV,IV_PLAT=mac",
				">CLIENT:ENV,IV_VER=3.8.1",
				">CLIENT:ENV,tls_serial_hex_0=51:b3:55:90:65:af:71:5c:d5:52:2b:0b:00:14:8d:ee",
				">CLIENT:ENV,tls_serial_0=108598624241397715647038806614705737198",
				">CLIENT:ENV,tls_digest_sha256_0=d3:6d:1d:96:f8:bd:7e:e8:db:c4:0f:53:a1:76:f0:ca:9e:78:63:bf:c6:4a:ac:b9:e6:ed:84:62:f5:ac:5d:b8",
				">CLIENT:ENV,tls_digest_0=b7:73:bd:6c:31:31:49:63:0d:0c:11:6d:0c:13:d0:b4:8f:97:33:7d",
				">CLIENT:ENV,tls_id_0=CN=user@example.com",
				">CLIENT:ENV,X509_0_CN=user@example.com",
				">CLIENT:ENV,tls_serial_hex_1=01:b3:95:f8:1a:9f:9f:fe:7c:27:ad:29:c1:93:23:ae:08:7f:ab:36",
				">CLIENT:ENV,tls_serial_1=9713888317380397892476539918183380788698917686",
				">CLIENT:ENV,tls_digest_sha256_1=75:1a:a1:63:bb:e9:c7:f3:e3:bf:e1:08:f1:36:b7:36:90:04:da:dd:b8:78:b1:cf:d5:ac:09:b6:36:31:a7:db",
				">CLIENT:ENV,tls_digest_1=d4:bc:00:89:e5:01:0c:27:3d:ea:4a:b5:42:8b:f7:3d:19:7a:a2:25",
				">CLIENT:ENV,tls_id_1=CN=Easy-RSA CA",
				">CLIENT:ENV,X509_1_CN=Easy-RSA CA",
				">CLIENT:ENV,remote_port_1=1194",
				">CLIENT:ENV,local_port_1=1194",
				">CLIENT:ENV,proto_1=udp",
				">CLIENT:ENV,daemon_pid=7",
				">CLIENT:ENV,daemon_start_time=1703401559",
				">CLIENT:ENV,daemon_log_redirect=0",
				">CLIENT:ENV,daemon=0",
				">CLIENT:ENV,verb=3",
				">CLIENT:ENV,config=/etc/openvpn/openvpn.conf",
				">CLIENT:ENV,ifconfig_local=100.64.0.1",
				">CLIENT:ENV,ifconfig_netmask=255.255.255.0",
				">CLIENT:ENV,script_context=init",
				">CLIENT:ENV,tun_mtu=1500",
				">CLIENT:ENV,dev=tun0",
				">CLIENT:ENV,dev_type=tun",
				">CLIENT:ENV,redirect_gateway=0",
				">CLIENT:ENV,END",
			}, "\r\n")

			testutils.SendMessagef(t, managementInterfaceConn, msg+"\r\n")

			authURL := testutils.ReadLine(t, managementInterfaceConn, reader)
			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-pending-auth command succeeded")

			_, authURL, _ = strings.Cut(authURL, `"`)
			authURL, _, _ = strings.Cut(authURL, `"`)
			authURL = strings.TrimPrefix(authURL, "WEB_AUTH::")

			request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL, nil)

			wg := sync.WaitGroup{}
			wg.Add(1)

			var resp *http.Response

			go func() {
				defer wg.Done()

				resp, err = httpClient.Do(request) //nolint:bodyclose
			}()

			testutils.ReadLine(t, managementInterfaceConn, reader)
			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")

			wg.Wait()

			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			require.NoError(t, err, buf.String())
			require.Equal(t, http.StatusOK, resp.StatusCode, buf.String())

			wg.Wait()
		})
	}
}
