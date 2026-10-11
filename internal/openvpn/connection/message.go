package connection

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MessageType classifies a message read from the OpenVPN management interface.
//
// See https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt
// ("OUTPUT FORMAT" and "REAL-TIME MESSAGE FORMAT").
type MessageType uint8

const (
	// MessageTypeUnknown is a real-time notification with an unknown source.
	// It is treated as a single line.
	MessageTypeUnknown MessageType = iota
	// MessageTypeSuccess is a single-line "SUCCESS:" command response.
	MessageTypeSuccess
	// MessageTypeError is a single-line "ERROR:" command response.
	MessageTypeError
	// MessageTypeResponse is a multi-line command response terminated by "END".
	MessageTypeResponse
	// MessageTypeClient is a ">CLIENT:" notification terminated by ">CLIENT:ENV,END".
	MessageTypeClient
	// MessageTypeClientAddress is a single-line ">CLIENT:ADDRESS" notification.
	MessageTypeClientAddress
	// MessageTypeUpDown is an ">UPDOWN:" notification terminated by ">UPDOWN:ENV,END".
	MessageTypeUpDown
	// MessageTypeBytecount and all following real-time notifications are single lines.
	MessageTypeBytecount
	MessageTypeBytecountCli
	MessageTypeEcho
	MessageTypeFatal
	MessageTypeHold
	MessageTypeInfo
	MessageTypeInfoMsg
	MessageTypeLog
	MessageTypeNeedCertificate
	MessageTypeNeedOk
	MessageTypeNeedStr
	MessageTypeNotify
	MessageTypePassword
	MessageTypePkSign
	MessageTypeProxy
	MessageTypeRemote
	MessageTypeRsaSign
	MessageTypeState
)

// String returns the protocol name of the message type.
//
//nolint:cyclop
func (t MessageType) String() string {
	switch t { //nolint:exhaustive // MessageTypeUnknown is handled by default
	case MessageTypeSuccess:
		return "SUCCESS"
	case MessageTypeError:
		return "ERROR"
	case MessageTypeResponse:
		return "RESPONSE"
	case MessageTypeClient:
		return "CLIENT"
	case MessageTypeClientAddress:
		return "CLIENT:ADDRESS"
	case MessageTypeUpDown:
		return "UPDOWN"
	case MessageTypeBytecount:
		return "BYTECOUNT"
	case MessageTypeBytecountCli:
		return "BYTECOUNT_CLI"
	case MessageTypeEcho:
		return "ECHO"
	case MessageTypeFatal:
		return "FATAL"
	case MessageTypeHold:
		return "HOLD"
	case MessageTypeInfo:
		return "INFO"
	case MessageTypeInfoMsg:
		return "INFOMSG"
	case MessageTypeLog:
		return "LOG"
	case MessageTypeNeedCertificate:
		return "NEED-CERTIFICATE"
	case MessageTypeNeedOk:
		return "NEED-OK"
	case MessageTypeNeedStr:
		return "NEED-STR"
	case MessageTypeNotify:
		return "NOTIFY"
	case MessageTypePassword:
		return "PASSWORD"
	case MessageTypePkSign:
		return "PK_SIGN"
	case MessageTypeProxy:
		return "PROXY"
	case MessageTypeRemote:
		return "REMOTE"
	case MessageTypeRsaSign:
		return "RSA_SIGN"
	case MessageTypeState:
		return "STATE"
	default:
		return "UNKNOWN"
	}
}

// Terminator returns the line that ends a message of this type. Messages of
// all other types consist of a single line, and Terminator returns an empty
// string for them.
func (t MessageType) Terminator() string {
	switch t { //nolint:exhaustive // all other message types are single-line
	case MessageTypeResponse:
		return "END"
	case MessageTypeClient:
		return ">CLIENT:ENV,END"
	case MessageTypeUpDown:
		return ">UPDOWN:ENV,END"
	default:
		return ""
	}
}

// parseNotificationSource maps the source keyword of a real-time notification
// (">SOURCE:...") to its message type.
//
//nolint:cyclop
func parseNotificationSource(source []byte) MessageType {
	switch string(source) {
	case "CLIENT":
		return MessageTypeClient
	case "UPDOWN":
		return MessageTypeUpDown
	case "BYTECOUNT":
		return MessageTypeBytecount
	case "BYTECOUNT_CLI":
		return MessageTypeBytecountCli
	case "ECHO":
		return MessageTypeEcho
	case "FATAL":
		return MessageTypeFatal
	case "HOLD":
		return MessageTypeHold
	case "INFO":
		return MessageTypeInfo
	case "INFOMSG":
		return MessageTypeInfoMsg
	case "LOG":
		return MessageTypeLog
	case "NEED-CERTIFICATE":
		return MessageTypeNeedCertificate
	case "NEED-OK":
		return MessageTypeNeedOk
	case "NEED-STR":
		return MessageTypeNeedStr
	case "NOTIFY":
		return MessageTypeNotify
	case "PASSWORD":
		return MessageTypePassword
	case "PK_SIGN":
		return MessageTypePkSign
	case "PROXY":
		return MessageTypeProxy
	case "REMOTE":
		return MessageTypeRemote
	case "RSA_SIGN":
		return MessageTypeRsaSign
	case "STATE":
		return MessageTypeState
	default:
		return MessageTypeUnknown
	}
}

// ParseMessageType classifies a message by its first line.
//
// Lines starting with '>' are real-time notifications. All other lines are
// command responses: "SUCCESS:" and "ERROR:" are single-line responses,
// everything else starts a multi-line response terminated by "END".
func ParseMessageType(line []byte) MessageType {
	switch {
	case bytes.HasPrefix(line, []byte("SUCCESS:")):
		return MessageTypeSuccess
	case bytes.HasPrefix(line, []byte("ERROR:")):
		return MessageTypeError
	case len(line) == 0 || line[0] != '>':
		return MessageTypeResponse
	}

	source, _, found := bytes.Cut(line[1:], []byte(":"))
	if !found {
		return MessageTypeUnknown
	}

	messageType := parseNotificationSource(source)
	if messageType == MessageTypeClient && isClientAddress(line) {
		return MessageTypeClientAddress
	}

	return messageType
}

func isClientAddress(line []byte) bool {
	rest, found := bytes.CutPrefix(line, []byte(">CLIENT:ADDRESS"))

	return found && (len(rest) == 0 || rest[0] == ',')
}

// ReadMessage reads the next complete message from scanner into buf. Each line
// is terminated by CRLF and empty lines are skipped. The first line determines
// the message type, and its terminator determines where the message ends.
//
// ReadMessage returns io.EOF if the scanner reaches the end of the input
// before a message is complete.
func ReadMessage(scanner *bufio.Scanner, buf *bytes.Buffer) (MessageType, error) {
	buf.Reset()

	var (
		messageType MessageType
		terminator  string
		started     bool
	)

	for scanner.Scan() {
		line := scanner.Bytes()

		if len(line) == 0 {
			continue
		}

		if !started {
			started = true
			messageType = ParseMessageType(line)
			terminator = messageType.Terminator()
		}

		buf.Write(line)
		buf.WriteString("\r\n")

		if terminator == "" || string(line) == terminator {
			return messageType, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return messageType, fmt.Errorf("scanner error: %w", err)
	}

	return messageType, io.EOF
}

// ParseClientAddress parses a ">CLIENT:ADDRESS,{CID},{ADDR},{PRI}" notification.
func ParseClientAddress(message string) (uint64, string, bool, error) {
	line := strings.TrimSpace(message)

	fields, found := strings.CutPrefix(line, ">CLIENT:ADDRESS,")
	if !found {
		return 0, "", false, fmt.Errorf("unable to parse line '%s': %w", line, ErrInvalidMessage)
	}

	cidString, fields, found := strings.Cut(fields, ",")
	if !found {
		return 0, "", false, fmt.Errorf("unable to parse line '%s': %w", line, ErrInvalidMessage)
	}

	addr, primary, found := strings.Cut(fields, ",")
	if !found || addr == "" {
		return 0, "", false, fmt.Errorf("unable to parse line '%s': %w", line, ErrInvalidMessage)
	}

	cid, err := strconv.ParseUint(cidString, 10, 64)
	if err != nil {
		return 0, "", false, fmt.Errorf("unable to parse cid: %w", err)
	}

	return cid, addr, primary == "1", nil
}
