package openvpn_test

import (
	"bufio"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func BenchmarkOpenVPNHandler(b *testing.B) {
	b.StopTimer()

	logger := testutils.NewTestLogger()
	managementInterface, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)

	defer managementInterface.Close()

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Addr:   &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()},
			Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}

	storageClient := storage.New(testutils.Secret, time.Hour)
	client := openvpn.NewClient(logger, conf, oauth2.New(logger, conf, storageClient))

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		err := client.Connect()
		if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
			require.NoError(b, err) //nolint:testifylint
		}
	}()

	managementInterfaceConn, err := managementInterface.Accept()
	require.NoError(b, err)

	defer managementInterfaceConn.Close()
	reader := bufio.NewReader(managementInterfaceConn)

	require.NoError(b, err)
	testutils.SendLine(b, managementInterfaceConn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
	assert.Equal(b, "hold release", testutils.ReadLine(b, reader))
	testutils.SendLine(b, managementInterfaceConn, "SUCCESS: hold release succeeded\r\n")
	assert.Equal(b, "version", testutils.ReadLine(b, reader))

	testutils.SendLine(b, managementInterfaceConn, "OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 5\r\nEND\r\n")

	tests := []struct {
		name   string
		client string
	}{
		{
			"short",
			">CLIENT:CONNECT,0,1\n>CLIENT:ENV,untrusted_ip=127.0.0.1\n>CLIENT:ENV,common_name=test\n>CLIENT:ENV,IV_SSO=webauth\n>CLIENT:ENV,END\n",
		},
		{
			"real",
			">CLIENT:CONNECT,0,1\n>CLIENT:ENV,n_clients=0\n>CLIENT:ENV,password=\n>CLIENT:ENV,untrusted_port=17016\n>CLIENT:ENV,untrusted_ip=192.168.65.1\n>CLIENT:ENV,common_name=user@example.com\n>CLIENT:ENV,username=\n>CLIENT:ENV,IV_BS64DL=1\n>CLIENT:ENV,IV_SSO=webauth,openurl,crtext\n>CLIENT:ENV,IV_GUI_VER=OCmacOS_3.4.4-4629\n>CLIENT:ENV,IV_AUTO_SESS=1\n>CLIENT:ENV,IV_CIPHERS=AES-128-GCM:AES-192-GCM:AES-256-GCM:CHACHA20-POLY1305\n>CLIENT:ENV,IV_MTU=1600\n>CLIENT:ENV,IV_PROTO=990\n>CLIENT:ENV,IV_TCPNL=1\n>CLIENT:ENV,IV_NCP=2\n>CLIENT:ENV,IV_PLAT=mac\n>CLIENT:ENV,IV_VER=3.8.1\n>CLIENT:ENV,tls_serial_hex_0=51:b3:55:90:65:af:71:5c:d5:52:2b:0b:00:14:8d:ee\n>CLIENT:ENV,tls_serial_0=108598624241397715647038806614705737198\n>CLIENT:ENV,tls_digest_sha256_0=d3:6d:1d:96:f8:bd:7e:e8:db:c4:0f:53:a1:76:f0:ca:9e:78:63:bf:c6:4a:ac:b9:e6:ed:84:62:f5:ac:5d:b8\n>CLIENT:ENV,tls_digest_0=b7:73:bd:6c:31:31:49:63:0d:0c:11:6d:0c:13:d0:b4:8f:97:33:7d\n>CLIENT:ENV,tls_id_0=CN=user@example.com\n>CLIENT:ENV,X509_0_CN=user@example.com\n>CLIENT:ENV,tls_serial_hex_1=01:b3:95:f8:1a:9f:9f:fe:7c:27:ad:29:c1:93:23:ae:08:7f:ab:36\n>CLIENT:ENV,tls_serial_1=9713888317380397892476539918183380788698917686\n>CLIENT:ENV,tls_digest_sha256_1=75:1a:a1:63:bb:e9:c7:f3:e3:bf:e1:08:f1:36:b7:36:90:04:da:dd:b8:78:b1:cf:d5:ac:09:b6:36:31:a7:db\n>CLIENT:ENV,tls_digest_1=d4:bc:00:89:e5:01:0c:27:3d:ea:4a:b5:42:8b:f7:3d:19:7a:a2:25\n>CLIENT:ENV,tls_id_1=CN=Easy-RSA CA\n>CLIENT:ENV,X509_1_CN=Easy-RSA CA\n>CLIENT:ENV,remote_port_1=1194\n>CLIENT:ENV,local_port_1=1194\n>CLIENT:ENV,proto_1=udp\n>CLIENT:ENV,daemon_pid=7\n>CLIENT:ENV,daemon_start_time=1703401559\n>CLIENT:ENV,daemon_log_redirect=0\n>CLIENT:ENV,daemon=0\n>CLIENT:ENV,verb=3\n>CLIENT:ENV,config=/etc/openvpn/openvpn.conf\n>CLIENT:ENV,ifconfig_local=100.64.0.1\n>CLIENT:ENV,ifconfig_netmask=255.255.255.0\n>CLIENT:ENV,script_context=init\n>CLIENT:ENV,tun_mtu=1500\n>CLIENT:ENV,dev=tun0\n>CLIENT:ENV,dev_type=tun\n>CLIENT:ENV,redirect_gateway=0\n>CLIENT:ENV,END\n",
		},
	}

	b.ResetTimer()
	b.StartTimer()

	for _, tt := range tests {
		tt := tt

		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				testutils.SendLine(b, managementInterfaceConn, tt.client)
				assert.Contains(b, testutils.ReadLine(b, reader), "client-pending-auth 0 1 \"WEB_AUTH::")
				testutils.SendLine(b, managementInterfaceConn, "SUCCESS: client-pending-auth command succeeded\r\n")
			}

			b.ReportAllocs()
		})
	}

	b.StopTimer()

	client.Shutdown()
	wg.Wait()
}
