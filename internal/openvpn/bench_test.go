package openvpn_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func BenchmarkOpenVPNHandler(b *testing.B) {
	b.StopTimer()

	ctx, cancel := context.WithCancel(b.Context())
	b.Cleanup(cancel)

	conf := config.Defaults
	conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
	conf.HTTP.Secret = testsuite.Secret
	conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)}

	suite := testsuite.New(&conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, b, nil)
	openVPNClient := suite.GetOpenVPNClient()
	managementInterfaceConn := suite.GetManagementInterfaceConn()

	suite.ExpectVersionAndReleaseHold(b)

	tests := []struct {
		name   string
		client string
	}{
		{
			"short",
			">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
		},
		{
			"real",
			">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,n_clients=0\r\n>CLIENT:ENV,password=\r\n>CLIENT:ENV,untrusted_port=17016\r\n>CLIENT:ENV,untrusted_ip=192.168.65.1\r\n>CLIENT:ENV,common_name=user@example.com\r\n>CLIENT:ENV,username=\r\n>CLIENT:ENV,IV_BS64DL=1\r\n>CLIENT:ENV,IV_SSO=webauth,openurl,crtext\r\n>CLIENT:ENV,IV_GUI_VER=OCmacOS_3.4.4-4629\r\n>CLIENT:ENV,IV_AUTO_SESS=1\r\n>CLIENT:ENV,IV_CIPHERS=AES-128-GCM:AES-192-GCM:AES-256-GCM:CHACHA20-POLY1305\r\n>CLIENT:ENV,IV_MTU=1600\r\n>CLIENT:ENV,IV_PROTO=990\r\n>CLIENT:ENV,IV_TCPNL=1\r\n>CLIENT:ENV,IV_NCP=2\r\n>CLIENT:ENV,IV_PLAT=mac\r\n>CLIENT:ENV,IV_VER=3.8.1\r\n>CLIENT:ENV,tls_serial_hex_0=51:b3:55:90:65:af:71:5c:d5:52:2b:0b:00:14:8d:ee\r\n>CLIENT:ENV,tls_serial_0=108598624241397715647038806614705737198\r\n>CLIENT:ENV,tls_digest_sha256_0=d3:6d:1d:96:f8:bd:7e:e8:db:c4:0f:53:a1:76:f0:ca:9e:78:63:bf:c6:4a:ac:b9:e6:ed:84:62:f5:ac:5d:b8\r\n>CLIENT:ENV,tls_digest_0=b7:73:bd:6c:31:31:49:63:0d:0c:11:6d:0c:13:d0:b4:8f:97:33:7d\r\n>CLIENT:ENV,tls_id_0=CN=user@example.com\r\n>CLIENT:ENV,X509_0_CN=user@example.com\r\n>CLIENT:ENV,tls_serial_hex_1=01:b3:95:f8:1a:9f:9f:fe:7c:27:ad:29:c1:93:23:ae:08:7f:ab:36\r\n>CLIENT:ENV,tls_serial_1=9713888317380397892476539918183380788698917686\r\n>CLIENT:ENV,tls_digest_sha256_1=75:1a:a1:63:bb:e9:c7:f3:e3:bf:e1:08:f1:36:b7:36:90:04:da:dd:b8:78:b1:cf:d5:ac:09:b6:36:31:a7:db\r\n>CLIENT:ENV,tls_digest_1=d4:bc:00:89:e5:01:0c:27:3d:ea:4a:b5:42:8b:f7:3d:19:7a:a2:25\r\n>CLIENT:ENV,tls_id_1=CN=Easy-RSA CA\r\n>CLIENT:ENV,X509_1_CN=Easy-RSA CA\r\n>CLIENT:ENV,remote_port_1=1194\r\n>CLIENT:ENV,local_port_1=1194\r\n>CLIENT:ENV,proto_1=udp\r\n>CLIENT:ENV,daemon_pid=7\r\n>CLIENT:ENV,daemon_start_time=1703401559\r\n>CLIENT:ENV,daemon_log_redirect=0\r\n>CLIENT:ENV,daemon=0\r\n>CLIENT:ENV,verb=3\r\n>CLIENT:ENV,config=/etc/openvpn/openvpn.conf\r\n>CLIENT:ENV,ifconfig_local=100.64.0.1\r\n>CLIENT:ENV,ifconfig_netmask=255.255.255.0\r\n>CLIENT:ENV,script_context=init\r\n>CLIENT:ENV,tun_mtu=1500\r\n>CLIENT:ENV,dev=tun0\r\n>CLIENT:ENV,dev_type=tun\r\n>CLIENT:ENV,redirect_gateway=0\r\n>CLIENT:ENV,END\r\n",
		},
	}

	b.ResetTimer()
	b.StartTimer()

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			for b.Loop() {
				suite.SendMessagef(b, tc.client)
				assert.Contains(b, suite.ReadLine(b), "client-pending-auth 0 1 \"WEB_AUTH::")
				suite.SendMessagef(b, "SUCCESS: client-pending-auth command succeeded")
			}

			b.ReportAllocs()
		})
	}

	b.StopTimer()

	openVPNClient.Shutdown(b.Context())
	require.NoError(b, managementInterfaceConn.Close())
	require.NoError(b, <-errOpenVPNClientCh)
}

func BenchmarkOpenVPNPassthrough(b *testing.B) {
	b.StopTimer()

	conf := config.Defaults
	conf.OpenVPN.Passthrough.Enabled = true
	conf.OpenVPN.Passthrough.Address = types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:0"}}
	conf.OpenVPN.Passthrough.Password = testsuite.Secret

	suite := testsuite.New(&conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(b.Context(), b, nil)
	openVPNClient := suite.GetOpenVPNClient()

	if conf.OpenVPN.Password != "" {
		suite.SendMessagef(b, "ENTER PASSWORD:")
		suite.ExpectMessage(b, conf.OpenVPN.Password.String())
		suite.SendMessagef(b, "SUCCESS: password is correct")
	}

	suite.ExpectVersionAndReleaseHold(b)

	var passThroughAddr []string

	for range 10 {
		passThroughAddr = rePassThroughLogListen.FindStringSubmatch(suite.Logs())
		if passThroughAddr != nil {
			break
		}

		time.Sleep(50 * time.Millisecond)
	}

	require.Len(b, passThroughAddr, 2, "unexpected log output: %s", suite.Logs())

	passThroughNetConn, err := testsuite.WaitUntilListening(b.Context(), b, "tcp", passThroughAddr[1])
	require.NoError(b, err)

	passThroughConn := testsuite.NewConn(passThroughNetConn)

	buf := make([]byte, len("ENTER PASSWORD:"))
	_, err = passThroughNetConn.Read(buf)
	require.NoError(b, err)
	require.Equal(b, "ENTER PASSWORD:", string(buf))

	passThroughConn.SendAndExpectMessage(b, testsuite.Secret, "SUCCESS: password is correct")

	tests := []struct {
		command  string
		response string
	}{
		{
			"pid",
			"SUCCESS: pid=7",
		},
		{
			"status",
			OpenVPNManagementInterfaceCommandResultStatus,
		},
		{
			"status 2",
			OpenVPNManagementInterfaceCommandResultStatus2,
		},
		{
			"help",
			OpenVPNManagementInterfaceCommandResultHelp,
		},
	}

	passThroughConn.ExpectMessage(b, openvpn.WelcomeBanner)

	b.Cleanup(func() {
		openVPNClient.Shutdown(b.Context())

		select {
		case err := <-errOpenVPNClientCh:
			require.NoError(b, err)
		case <-time.After(1 * time.Second):
			b.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
		}
	})

	b.ResetTimer()
	b.StartTimer()

	for _, tc := range tests {
		b.Run(tc.command, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				passThroughConn.SendMessagef(b, tc.command)
				suite.ExpectMessage(b, tc.command)
				suite.SendMessagef(b, tc.response)
				passThroughConn.ExpectMessage(b, tc.response)
			}
		})
	}

	b.StopTimer()
}
