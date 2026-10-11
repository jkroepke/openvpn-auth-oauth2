package connection_test

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMessageType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		line        string
		messageType connection.MessageType
	}{
		{"SUCCESS: hold release succeeded", connection.MessageTypeSuccess},
		{"ERROR: unknown command, enter 'help' for more options", connection.MessageTypeError},
		{"OpenVPN Version: OpenVPN 2.6.14", connection.MessageTypeResponse},
		{"END", connection.MessageTypeResponse},
		{"ENGINEERING,1.2.3.4:1194", connection.MessageTypeResponse},
		{">BYTECOUNT:1024,2048", connection.MessageTypeBytecount},
		{">BYTECOUNT_CLI:1,1024,2048", connection.MessageTypeBytecountCli},
		{">CLIENT:CONNECT,0,1", connection.MessageTypeClient},
		{">CLIENT:REAUTH,0,1", connection.MessageTypeClient},
		{">CLIENT:ESTABLISHED,0", connection.MessageTypeClient},
		{">CLIENT:DISCONNECT,0", connection.MessageTypeClient},
		{">CLIENT:CR_RESPONSE,0,1,YmFzZTY0", connection.MessageTypeClient},
		{">CLIENT:ADDRESS,0,10.8.0.2,1", connection.MessageTypeClientAddress},
		{">CLIENT:ADDRESS", connection.MessageTypeClientAddress},
		{">CLIENT:ADDRESSX,0", connection.MessageTypeClient},
		{">ECHO:1101519562,forget-passwords", connection.MessageTypeEcho},
		{">FATAL:Cannot open TUN/TAP dev", connection.MessageTypeFatal},
		{">HOLD:Waiting for hold release:0", connection.MessageTypeHold},
		{">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info", connection.MessageTypeInfo},
		{">INFOMSG:OPEN_URL:https://example.com", connection.MessageTypeInfoMsg},
		{">LOG:1101519562,I,Initialization Sequence Completed", connection.MessageTypeLog},
		{">NEED-CERTIFICATE:macosx-keychain:subject:o=OpenVPN-TEST", connection.MessageTypeNeedCertificate},
		{">NEED-OK:Need 'token-insertion-request' confirmation MSG:Please insert your cryptographic token", connection.MessageTypeNeedOk},
		{">NEED-STR:Need 'name' input MSG:Please specify your name", connection.MessageTypeNeedStr},
		{">NOTIFY:info,remote-exit,EXIT", connection.MessageTypeNotify},
		{">PASSWORD:Need 'Auth' username/password", connection.MessageTypePassword},
		{">PK_SIGN:dGVzdA==,RSA_PKCS1_PADDING", connection.MessageTypePkSign},
		{">PROXY:1,TCP,vpn.example.com", connection.MessageTypeProxy},
		{">REMOTE:vpn.example.com,1194,udp", connection.MessageTypeRemote},
		{">RSA_SIGN:dGVzdA==", connection.MessageTypeRsaSign},
		{">STATE:1101519562,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,", connection.MessageTypeState},
		{">UPDOWN:UP", connection.MessageTypeUpDown},
		{">FOO:bar", connection.MessageTypeUnknown},
		{">FOO", connection.MessageTypeUnknown},
		{">", connection.MessageTypeUnknown},
	} {
		t.Run(tc.line, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.messageType, connection.ParseMessageType([]byte(tc.line)))
		})
	}
}

func TestMessageTypeString(t *testing.T) {
	t.Parallel()

	for messageType, name := range map[connection.MessageType]string{
		connection.MessageTypeSuccess:  "SUCCESS",
		connection.MessageTypeError:    "ERROR",
		connection.MessageTypeResponse: "RESPONSE",
		connection.MessageTypeUnknown:  "UNKNOWN",
		connection.MessageType(255):    "UNKNOWN",
	} {
		assert.Equal(t, name, messageType.String())
	}

	assert.Equal(t, "CLIENT:ADDRESS", connection.MessageTypeClientAddress.String())
	assert.Equal(t, connection.MessageTypeClientAddress, connection.ParseMessageType([]byte(">CLIENT:ADDRESS,0,10.8.0.2,1")))

	// The name of every real-time notification type round-trips through ParseMessageType.
	for messageType := connection.MessageTypeClient; messageType <= connection.MessageTypeState; messageType++ {
		if messageType == connection.MessageTypeClientAddress {
			continue
		}

		line := ">" + messageType.String() + ":"
		assert.Equal(t, messageType, connection.ParseMessageType([]byte(line)), line)
	}
}

func TestReadMessage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		input    string
		messages []string
		types    []connection.MessageType
	}{
		{
			name:     "single-line responses",
			input:    "SUCCESS: pid=7\r\nERROR: unknown command\r\n",
			messages: []string{"SUCCESS: pid=7\r\n", "ERROR: unknown command\r\n"},
			types:    []connection.MessageType{connection.MessageTypeSuccess, connection.MessageTypeError},
		},
		{
			name:     "multi-line response",
			input:    "OpenVPN Version: OpenVPN Mock\r\nManagement Version: 5\r\nEND\r\n",
			messages: []string{"OpenVPN Version: OpenVPN Mock\r\nManagement Version: 5\r\nEND\r\n"},
			types:    []connection.MessageType{connection.MessageTypeResponse},
		},
		{
			name:     "empty multi-line response",
			input:    "END\r\n",
			messages: []string{"END\r\n"},
			types:    []connection.MessageType{connection.MessageTypeResponse},
		},
		{
			name: "multi-line response with lines starting like terminators",
			input: "OpenVPN CLIENT LIST\r\nCommon Name,Real Address\r\nENGINEERING,1.2.3.4:1194\r\n" +
				"SUPPORT,1.2.3.5:1194\r\nERIC,1.2.3.6:1194\r\nEND\r\n",
			messages: []string{
				"OpenVPN CLIENT LIST\r\nCommon Name,Real Address\r\nENGINEERING,1.2.3.4:1194\r\n" +
					"SUPPORT,1.2.3.5:1194\r\nERIC,1.2.3.6:1194\r\nEND\r\n",
			},
			types: []connection.MessageType{connection.MessageTypeResponse},
		},
		{
			name:     "client notification",
			input:    ">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,END\r\n",
			messages: []string{">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,END\r\n"},
			types:    []connection.MessageType{connection.MessageTypeClient},
		},
		{
			name:  "client address before client established",
			input: ">CLIENT:ADDRESS,0,10.8.0.2,1\r\n>CLIENT:ESTABLISHED,0\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,END\r\n",
			messages: []string{
				">CLIENT:ADDRESS,0,10.8.0.2,1\r\n",
				">CLIENT:ESTABLISHED,0\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,END\r\n",
			},
			types: []connection.MessageType{connection.MessageTypeClientAddress, connection.MessageTypeClient},
		},
		{
			name:     "client address before command response",
			input:    ">CLIENT:ADDRESS,0,10.8.0.2,1\r\nSUCCESS: pid=7\r\n",
			messages: []string{">CLIENT:ADDRESS,0,10.8.0.2,1\r\n", "SUCCESS: pid=7\r\n"},
			types:    []connection.MessageType{connection.MessageTypeClientAddress, connection.MessageTypeSuccess},
		},
		{
			name:  "single-line notifications before client notification",
			input: ">BYTECOUNT_CLI:1,1024,2048\r\n>STATE:1,CONNECTED,SUCCESS\r\n>LOG:1,I,log\r\n>CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,END\r\n",
			messages: []string{
				">BYTECOUNT_CLI:1,1024,2048\r\n",
				">STATE:1,CONNECTED,SUCCESS\r\n",
				">LOG:1,I,log\r\n",
				">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,END\r\n",
			},
			types: []connection.MessageType{
				connection.MessageTypeBytecountCli,
				connection.MessageTypeState,
				connection.MessageTypeLog,
				connection.MessageTypeClient,
			},
		},
		{
			name:     "unknown notification is a single line",
			input:    ">FOO:bar\r\nSUCCESS: pid=7\r\n",
			messages: []string{">FOO:bar\r\n", "SUCCESS: pid=7\r\n"},
			types:    []connection.MessageType{connection.MessageTypeUnknown, connection.MessageTypeSuccess},
		},
		{
			name:     "updown notification",
			input:    ">UPDOWN:UP\r\n>UPDOWN:ENV,dev=tun0\r\n>UPDOWN:ENV,END\r\n>HOLD:Waiting for hold release:0\r\n",
			messages: []string{">UPDOWN:UP\r\n>UPDOWN:ENV,dev=tun0\r\n>UPDOWN:ENV,END\r\n", ">HOLD:Waiting for hold release:0\r\n"},
			types:    []connection.MessageType{connection.MessageTypeUpDown, connection.MessageTypeHold},
		},
		{
			name:     "empty lines and LF line endings",
			input:    "\r\n\n>HOLD:Waiting for hold release:0\n\nSUCCESS: hold release succeeded\n",
			messages: []string{">HOLD:Waiting for hold release:0\r\n", "SUCCESS: hold release succeeded\r\n"},
			types:    []connection.MessageType{connection.MessageTypeHold, connection.MessageTypeSuccess},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scanner := bufio.NewScanner(strings.NewReader(tc.input))

			var buf bytes.Buffer

			for i := range tc.messages {
				messageType, err := connection.ReadMessage(scanner, &buf)
				require.NoError(t, err)
				assert.Equal(t, tc.types[i], messageType)
				assert.Equal(t, tc.messages[i], buf.String())
			}

			_, err := connection.ReadMessage(scanner, &buf)
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestReadMessageIncomplete(t *testing.T) {
	t.Parallel()

	scanner := bufio.NewScanner(strings.NewReader(">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,common_name=test\r\n"))

	var buf bytes.Buffer

	messageType, err := connection.ReadMessage(scanner, &buf)
	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, connection.MessageTypeClient, messageType)
}

func TestParseClientAddress(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		message string
		addr    string
		err     string
		cid     uint64
		primary bool
	}{
		{message: ">CLIENT:ADDRESS,3,10.8.0.2,1\r\n", cid: 3, addr: "10.8.0.2", primary: true},
		{message: ">CLIENT:ADDRESS,3,10.9.0.0/24,0", cid: 3, addr: "10.9.0.0/24", primary: false},
		{message: ">CLIENT:ADDRESS,3,fd00::2,1", cid: 3, addr: "fd00::2", primary: true},
		{message: ">CLIENT:ADDRESS,127.0.0.1", err: "unable to parse line '>CLIENT:ADDRESS,127.0.0.1': message invalid"},
		{message: ">CLIENT:ADDRESS", err: "unable to parse line '>CLIENT:ADDRESS': message invalid"},
		{message: ">CLIENT:ADDRESS,3,,1", err: "unable to parse line '>CLIENT:ADDRESS,3,,1': message invalid"},
		{message: ">CLIENT:ADDRESS,a,10.8.0.2,1", err: "unable to parse cid: strconv.ParseUint: parsing \"a\": invalid syntax"},
	} {
		t.Run(tc.message, func(t *testing.T) {
			t.Parallel()

			cid, addr, primary, err := connection.ParseClientAddress(tc.message)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.cid, cid)
			assert.Equal(t, tc.addr, addr)
			assert.Equal(t, tc.primary, primary)
		})
	}
}
