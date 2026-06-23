package internal_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func BenchmarkFull(b *testing.B) {
	b.StopTimer()

	suite := testsuite.New(config.Config{})
	suite.SetupMockEnvironment(b.Context(), b, nil)
	suite.ExpectVersionAndReleaseHold(b)

	clientConnectMessage := strings.Join([]string{
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
		">CLIENT:ENV,IV_CIPHERS=AES-128-GCM:AES-192-GCM:CHACHA20-POLY1305",
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
	}, "\r\n") + "\r\n"

	var authURL string

	b.ResetTimer()
	b.StartTimer()

	for b.Loop() {
		suite.SendMessagef(b, clientConnectMessage)

		authURL = testsuite.GetAuthURLFromMessage(suite.ReadLine(b))
		suite.SendMessagef(b, "SUCCESS: client-pending-auth command succeeded")

		_, _, err := suite.DoHTTPRequest(b, http.MethodGet, authURL, nil, http.NoBody) //nolint:bodyclose
		require.NoError(b, err)

		suite.ExpectMessage(b, "client-auth-nt 0 1")
		suite.SendMessagef(b, "SUCCESS: client-auth command succeeded")
	}

	b.StopTimer()

	suite.Close(b)

	b.ReportAllocs()
}
