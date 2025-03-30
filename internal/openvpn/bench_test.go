package openvpn_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func BenchmarkOpenVPNHandler(b *testing.B) {
	b.StopTimer()

	ctx, cancel := context.WithCancel(b.Context())
	b.Cleanup(cancel)

	logger := testutils.NewTestLogger()
	managementInterface, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)

	b.Cleanup(func() {
		require.NoError(b, managementInterface.Close())
	})

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Addr:   &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()},
			Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}

	tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, b, conf, logger.Logger, http.DefaultClient, tokenStorage)

	managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(b, managementInterface, openVPNClient)
	require.NoError(b, err)

	reader := bufio.NewReader(managementInterfaceConn)
	require.NoError(b, err)

	testutils.ExpectVersionAndReleaseHold(b, managementInterfaceConn, reader)

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

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			for b.Loop() {
				testutils.SendMessage(b, managementInterfaceConn, tt.client)
				assert.Contains(b, testutils.ReadLine(b, managementInterfaceConn, reader), "client-pending-auth 0 1 \"WEB_AUTH::")
				testutils.SendMessage(b, managementInterfaceConn, "SUCCESS: client-pending-auth command succeeded")
			}

			b.ReportAllocs()
		})
	}

	b.StopTimer()

	openVPNClient.Shutdown()
	require.NoError(b, <-errOpenVPNClientCh)
}

func BenchmarkOpenVPNPassthrough(b *testing.B) {
	b.StopTimer()

	logger := testutils.NewTestLogger()

	conf := config.Defaults
	conf.HTTP.Secret = testutils.Secret
	conf.OpenVpn.Passthrough.Enabled = true

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(b, err)

	b.Cleanup(func() {
		require.NoError(b, managementInterface.Close())
	})

	passThroughInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(b, err)

	conf.OpenVpn.Passthrough.Address = &config.URL{Scheme: "tcp", Host: passThroughInterface.Addr().String()}
	conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

	passThroughInterface.Close()

	ctx, cancel := context.WithCancelCause(b.Context())

	b.Cleanup(func() {
		cancel(nil)
	})

	tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, b, conf, logger.Logger, http.DefaultClient, tokenStorage)

	wg := sync.WaitGroup{}

	wg.Add(1)

	go func() {
		defer wg.Done()

		managementInterfaceConn, err := managementInterface.Accept()
		if err != nil {
			cancel(fmt.Errorf("accepting connection: %w", err))

			return
		}

		defer managementInterfaceConn.Close()

		reader := bufio.NewReader(managementInterfaceConn)

		if conf.OpenVpn.Password != "" {
			testutils.SendMessage(b, managementInterfaceConn, "ENTER PASSWORD:")
			testutils.ExpectMessage(b, managementInterfaceConn, reader, conf.OpenVpn.Password.String())
			testutils.SendMessage(b, managementInterfaceConn, "SUCCESS: password is correct")
		}

		testutils.ExpectVersionAndReleaseHold(b, managementInterfaceConn, reader)

		var message string

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				cancel(fmt.Errorf("reading line: %w", err))

				return
			}

			line = strings.TrimSpace(line)

			if line == "exit" {
				cancel(nil)

				break
			}

			switch line {
			case "help":
				message = OpenVPNManagementInterfaceCommandResultHelp
			case "status":
				message = OpenVPNManagementInterfaceCommandResultStatus
			case "status 2":
				message = OpenVPNManagementInterfaceCommandResultStatus2
			case "version":
				message = "OpenVPN Version: openvpn-auth-oauth2\r\nManagement Interface Version: 5\r\nEND"
			case "load-stats":
				message = "SUCCESS: nclients=0,bytesin=0,bytesout=0"
			case "pid":
				message = "SUCCESS: pid=7"
			case "kill 1":
				message = "ERROR: common name '1' not found"
			case "client-kill 1":
				message = "ERROR: client-kill command failed"
			default:
				message = "ERROR: unknown command, enter 'help' for more options"
			}

			testutils.SendMessage(b, managementInterfaceConn, message+"")
		}
	}()

	wg.Add(1)

	go func() {
		defer wg.Done()

		err := openVPNClient.Connect(b.Context())
		if err != nil {
			cancel(fmt.Errorf("connecting: %w", err))

			return
		}

		<-ctx.Done()
	}()

	var passThroughConn net.Conn

	for range 10 {
		passThroughConn, err = net.DialTimeout(passThroughInterface.Addr().Network(), passThroughInterface.Addr().String(), time.Second)
		if err == nil {
			break
		}

		if errors.Is(err, syscall.ECONNREFUSED) {
			time.Sleep(100 * time.Millisecond)

			continue
		}

		require.NoError(b, err)
	}

	require.NoError(b, err)

	passThroughReader := bufio.NewReader(passThroughConn)

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

	b.Cleanup(func() {
		testutils.SendMessage(b, passThroughConn, "exit")
		openVPNClient.Shutdown()
		wg.Wait()

		<-ctx.Done()

		if err := context.Cause(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			require.NoError(b, err)
		}
	})

	testutils.ExpectMessage(b, passThroughConn, passThroughReader, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")

	b.ResetTimer()
	b.StartTimer()

	for _, tt := range tests {
		b.Run(tt.command, func(b *testing.B) {
			testutils.SendAndExpectMessage(b, passThroughConn, passThroughReader, tt.command, tt.response)

			b.ReportAllocs()
		})
	}

	b.StopTimer()
}
