package state

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/crypto"
)

const (
	binaryStateVersion = 2

	flagSessionID         = 1 << 0
	flagCommonName        = 1 << 1
	flagIPAddrV4          = 1 << 2
	flagIPAddrV6          = 1 << 3
	flagIPAddrText        = 1 << 4
	flagIPPort            = 1 << 5
	flagUsernameIsDefined = 1 << 6
)

// State represents the context and security information associated with an OAuth2 login flow.
//
// The `State` value is passed to the `state` GET parameter during the OAuth2 login flow.
// It ensures that the client initiating the login flow is the same client completing it,
// thus preventing CSRF (Cross-Site Request Forgery) attacks. The `State` value is returned
// by the OAuth2 Identity Provider (IDP) in the redirect URL.
//
// To prevent tampering, the `State` is protected using Salsa20 + HMAC encryption.
type State struct {
	IPAddr       string
	IPPort       string
	SessionState string
	Client       ClientIdentifier
}

type EncryptedState = string

// ClientIdentifier holds detailed information about the client initiating an OAuth2 login flow.
//
// This struct provides more context for the client and can be passed to [github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn.Client.AcceptClient].
type ClientIdentifier struct {
	SessionID         string // OpenVPN session identifier
	CommonName        string // OpenVPN common name (user)
	CID               uint64 // OpenVPN connection ID
	KID               uint64 // OpenVPN key ID
	UsernameIsDefined int    // 1 if username is defined, 0 otherwise
}

// Encrypt serializes the state into a compact binary, Salsa20-encrypted, base64-URL-safe string.
// The result is safe for use in URL parameters and has a ~1-second resolution timestamp.
func Encrypt(cipher *crypto.Cipher, state State) (EncryptedState, error) {
	if cipher == nil {
		return "", errors.New("cipher is required")
	}

	data := encodeState(state)

	encrypted, err := cipher.EncryptBytesWithTime(data)
	if err != nil {
		return "", fmt.Errorf("encrypt state: %w", err)
	}

	return EncryptedState(encrypted), nil
}

// Decrypt authenticates, decrypts, and deserializes an encrypted OAuth2 state value.
func Decrypt(cipher *crypto.Cipher, encryptedState EncryptedState) (State, error) {
	if cipher == nil {
		return State{}, errors.New("cipher is required")
	}

	data, err := cipher.DecryptBytesWithTime([]byte(encryptedState))
	if err != nil {
		return State{}, fmt.Errorf("decrypt state: %w", err)
	}

	state, err := decodeState(data)
	if err != nil {
		return State{}, fmt.Errorf("decode state: %w", err)
	}

	return state, nil
}

// encodeState serializes State into the compact binary payload protected by Encrypt.
func encodeState(state State) []byte {
	data := make([]byte, 0, 4+
		binary.MaxVarintLen64*2+
		len(state.Client.SessionID)+
		len(state.Client.CommonName)+
		len(state.IPAddr)+
		len(state.IPPort))

	flags, ipAddr := encodeStateFlags(state)

	data = append(data, binaryStateVersion, flags, encodeSessionState(state.SessionState)[0])

	data = appendUvarint(data, state.Client.CID)
	data = appendUvarint(data, state.Client.KID)

	if flags&flagSessionID != 0 {
		data = appendString(data, state.Client.SessionID)
	}

	if flags&flagCommonName != 0 {
		data = appendString(data, state.Client.CommonName)
	}

	switch {
	case flags&flagIPAddrV4 != 0:
		ipBytes := ipAddr.As4()
		data = append(data, ipBytes[:]...)
	case flags&flagIPAddrV6 != 0:
		ipBytes := ipAddr.As16()
		data = append(data, ipBytes[:]...)
	case flags&flagIPAddrText != 0:
		data = appendString(data, state.IPAddr)
	}

	if flags&flagIPPort != 0 {
		data = appendString(data, state.IPPort)
	}

	return data
}

// encodeStateFlags derives the optional-field bitset and parsed IP address for binary state encoding.
func encodeStateFlags(state State) (byte, netip.Addr) {
	var (
		flags  byte
		ipAddr netip.Addr
	)

	if state.Client.SessionID != "" {
		flags |= flagSessionID
	}

	if state.Client.CommonName != "" {
		flags |= flagCommonName
	}

	if state.Client.UsernameIsDefined != 0 {
		flags |= flagUsernameIsDefined
	}

	if state.IPPort != "" {
		flags |= flagIPPort
	}

	if state.IPAddr == "" {
		return flags, ipAddr
	}

	addr, err := netip.ParseAddr(state.IPAddr)
	if err != nil || addr.String() != state.IPAddr {
		flags |= flagIPAddrText

		return flags, ipAddr
	}

	if addr.Is4() {
		flags |= flagIPAddrV4
	} else {
		flags |= flagIPAddrV6
	}

	return flags, addr
}

// decodeState parses a compact binary state payload after cryptographic verification.
func decodeState(data []byte) (State, error) {
	if len(data) < 3 {
		return State{}, fmt.Errorf("state is too short: %d bytes", len(data))
	}

	if data[0] != binaryStateVersion {
		return State{}, fmt.Errorf("unsupported state version: %d", data[0])
	}

	flags := data[1]
	sessionState := decodeSessionState(string(data[2]))
	data = data[3:]

	cid, data, err := readUvarint(data)
	if err != nil {
		return State{}, fmt.Errorf("read CID: %w", err)
	}

	kid, data, err := readUvarint(data)
	if err != nil {
		return State{}, fmt.Errorf("read KID: %w", err)
	}

	state := State{
		Client: ClientIdentifier{
			CID:               cid,
			KID:               kid,
			UsernameIsDefined: boolToInt(flags&flagUsernameIsDefined != 0),
		},
		SessionState: sessionState,
	}

	return decodeStateFields(state, flags, data)
}

// decodeStateFields reads the optional fields controlled by the state flags.
func decodeStateFields(state State, flags byte, data []byte) (State, error) {
	var err error

	if flags&flagSessionID != 0 {
		state.Client.SessionID, data, err = readString(data)
		if err != nil {
			return State{}, fmt.Errorf("read SessionID: %w", err)
		}
	}

	if flags&flagCommonName != 0 {
		state.Client.CommonName, data, err = readString(data)
		if err != nil {
			return State{}, fmt.Errorf("read CommonName: %w", err)
		}
	}

	state.IPAddr, data, err = readIPAddr(flags, data)
	if err != nil {
		return State{}, fmt.Errorf("read IPAddr: %w", err)
	}

	if flags&flagIPPort != 0 {
		state.IPPort, data, err = readString(data)
		if err != nil {
			return State{}, fmt.Errorf("read IPPort: %w", err)
		}
	}

	if len(data) != 0 {
		return State{}, fmt.Errorf("unexpected trailing state data: %d bytes", len(data))
	}

	return state, nil
}

// readIPAddr reads the IP address field indicated by the state flags.
func readIPAddr(flags byte, data []byte) (string, []byte, error) {
	switch {
	case flags&flagIPAddrV4 != 0:
		return readIPAddrV4(data)
	case flags&flagIPAddrV6 != 0:
		return readIPAddrV6(data)
	case flags&flagIPAddrText != 0:
		return readString(data)
	default:
		return "", data, nil
	}
}

// appendString appends a length-prefixed string to the binary state payload.
func appendString(data []byte, text string) []byte {
	data = appendUvarint(data, uint64(len(text)))

	return append(data, text...)
}

// appendUvarint appends a uint64 using Go's compact unsigned varint encoding.
func appendUvarint(data []byte, value uint64) []byte {
	var scratch [binary.MaxVarintLen64]byte

	n := binary.PutUvarint(scratch[:], value)

	return append(data, scratch[:n]...)
}

// readString reads a length-prefixed string from a binary state payload.
func readString(data []byte) (string, []byte, error) {
	length, data, err := readUvarint(data)
	if err != nil {
		return "", nil, err
	}

	if uint64(len(data)) < length {
		return "", nil, fmt.Errorf("string length %d exceeds remaining data %d", length, len(data))
	}

	return string(data[:length]), data[length:], nil
}

// readUvarint reads an unsigned varint and returns the remaining payload.
func readUvarint(data []byte) (uint64, []byte, error) {
	value, readLen := binary.Uvarint(data)
	if readLen <= 0 {
		return 0, nil, errors.New("invalid uvarint")
	}

	return value, data[readLen:], nil
}

// readIPAddrV4 reads a raw four-byte IPv4 address from a binary state payload.
func readIPAddrV4(data []byte) (string, []byte, error) {
	if len(data) < 4 {
		return "", nil, fmt.Errorf("ipv4 length exceeds remaining data %d", len(data))
	}

	var ipBytes [4]byte
	copy(ipBytes[:], data[:4])

	return netip.AddrFrom4(ipBytes).String(), data[4:], nil
}

// readIPAddrV6 reads a raw 16-byte IPv6 address from a binary state payload.
func readIPAddrV6(data []byte) (string, []byte, error) {
	if len(data) < 16 {
		return "", nil, fmt.Errorf("ipv6 length exceeds remaining data %d", len(data))
	}

	var ipBytes [16]byte
	copy(ipBytes[:], data[:16])

	return netip.AddrFrom16(ipBytes).String(), data[16:], nil
}

// boolToInt converts a boolean flag to the integer representation used by ClientIdentifier.
func boolToInt(value bool) int {
	if value {
		return 1
	}

	return 0
}
