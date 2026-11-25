package state

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/crypto"
)

const (
	// binaryStateVersion is written by Encrypt. Version 3 stores a hexadecimal
	// nonce as raw bytes, see appendNonce.
	binaryStateVersion = 3
	// binaryStateVersionTextNonce is still accepted by Decrypt, so states
	// issued by an older release before an upgrade remain valid.
	binaryStateVersionTextNonce = 2

	// stateEncodingScratchSize covers typical states while retaining a heap fallback for larger values.
	stateEncodingScratchSize = 128
	// stateDecryptionScratchSize covers the encoded ciphertext for typical states.
	stateDecryptionScratchSize = stateEncodingScratchSize + 64
	// stateStringScratchSize covers the decoded string fields for typical states.
	stateStringScratchSize = 128

	// ipAddrTextScratchSize holds any canonical IP address without a zone.
	ipAddrTextScratchSize = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

	flagSessionID         = 1 << 0
	flagCommonName        = 1 << 1
	flagIPAddrV4          = 1 << 2
	flagIPAddrV6          = 1 << 3
	flagIPAddrText        = 1 << 4
	flagIPPort            = 1 << 5
	flagUsernameIsDefined = 1 << 6
	flagNonce             = 1 << 7
)

// State represents the context and security information associated with an OAuth2 login flow.
//
// The `State` value is passed to the `state` GET parameter during the OAuth2 login flow.
// It ensures that the client initiating the login flow is the same client completing it,
// thus preventing CSRF (Cross-Site Request Forgery) attacks. The `State` value is returned
// by the OAuth2 Identity Provider (IDP) in the redirect URL.
//
// To prevent tampering, the State is protected using AES-256-GCM.
type State struct {
	IPAddr       string
	IPPort       string
	SessionState string
	// Nonce is the OIDC nonce sent with the authorization request. It is
	// random per login and the ID token returned for this state must carry it.
	Nonce  string
	Client ClientIdentifier
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

// Encrypt serializes the state into a compact binary, authenticated, base64-URL-safe string.
// The result is safe for use in URL parameters and has a ~1-second resolution timestamp.
func Encrypt(cipher *crypto.Cipher, state State) (EncryptedState, error) {
	if cipher == nil {
		return "", errors.New("cipher is required")
	}

	var scratch [stateEncodingScratchSize]byte

	data := encodeState(scratch[:0], state)

	encrypted, err := cipher.EncryptStringWithTime(data)
	if err != nil {
		return "", fmt.Errorf("encrypt state: %w", err)
	}

	return encrypted, nil
}

// Decrypt authenticates, decrypts, and deserializes an encrypted OAuth2 state value.
func Decrypt(cipher *crypto.Cipher, encryptedState EncryptedState) (State, error) {
	if cipher == nil {
		return State{}, errors.New("cipher is required")
	}

	var scratch [stateDecryptionScratchSize]byte

	data := scratch[:]

	dataLen, err := cipher.DecryptStringWithTimeInto(data, encryptedState)
	if errors.Is(err, io.ErrShortBuffer) {
		data = make([]byte, dataLen)
		dataLen, err = cipher.DecryptStringWithTimeInto(data, encryptedState)
	}

	if err != nil {
		return State{}, fmt.Errorf("decrypt state: %w", err)
	}

	state, err := decodeState(data[:dataLen])
	if err != nil {
		return State{}, fmt.Errorf("decode state: %w", err)
	}

	return state, nil
}

// encodeState appends State as the compact binary payload protected by Encrypt.
func encodeState(data []byte, state State) []byte {
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

	if flags&flagNonce != 0 {
		data = appendNonce(data, state.Nonce)
	}

	return data
}

// appendNonce appends the nonce field. Its uvarint header holds the length
// shifted left by one; the low bit marks a nonce stored as raw bytes. A
// lowercase hexadecimal nonce, as generated for OIDC logins, is stored raw at
// half its text size, which matters because the encrypted state must fit into a
// single OpenVPN management parameter. Any other value is stored as text.
func appendNonce(data []byte, nonce string) []byte {
	if !isLowerHex(nonce) {
		data = appendUvarint(data, uint64(len(nonce))<<1)

		return append(data, nonce...)
	}

	data = appendUvarint(data, uint64(len(nonce)/2)<<1|1)

	// isLowerHex guarantees valid input, so decoding cannot fail.
	data, _ = hex.AppendDecode(data, []byte(nonce))

	return data
}

// isLowerHex reports whether text is a non-empty, even-length, lowercase hexadecimal string.
func isLowerHex(text string) bool {
	if text == "" || len(text)%2 != 0 {
		return false
	}

	for i := range len(text) {
		if c := text[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}

// readNonce reads the nonce field written by appendNonce into scratch.
func readNonce(data, scratch []byte) ([]byte, []byte, error) {
	header, data, err := readUvarint(data)
	if err != nil {
		return nil, nil, err
	}

	length := header >> 1

	if uint64(len(data)) < length {
		return nil, nil, fmt.Errorf("nonce length %d exceeds remaining data %d", length, len(data))
	}

	if header&1 == 0 {
		return data[:length], data[length:], nil
	}

	return hex.AppendEncode(scratch, data[:length]), data[length:], nil
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

	if state.Nonce != "" {
		flags |= flagNonce
	}

	if state.IPAddr == "" {
		return flags, ipAddr
	}

	addr, err := netip.ParseAddr(state.IPAddr)
	if err != nil {
		flags |= flagIPAddrText

		return flags, ipAddr
	}

	var scratch [ipAddrTextScratchSize]byte

	if string(addr.AppendTo(scratch[:0])) != state.IPAddr {
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

	version := data[0]
	if version != binaryStateVersion && version != binaryStateVersionTextNonce {
		return State{}, fmt.Errorf("unsupported state version: %d", version)
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

	return decodeStateFields(state, version, flags, data)
}

// decodeStateFields reads the optional fields controlled by the state flags.
func decodeStateFields(state State, version, flags byte, data []byte) (State, error) {
	sessionID, data, err := readFlaggedString(flags, flagSessionID, data, "SessionID")
	if err != nil {
		return State{}, err
	}

	commonName, data, err := readFlaggedString(flags, flagCommonName, data, "CommonName")
	if err != nil {
		return State{}, err
	}

	var ipAddrScratch [ipAddrTextScratchSize]byte

	ipAddr, data, err := readIPAddr(flags, data, ipAddrScratch[:0])
	if err != nil {
		return State{}, fmt.Errorf("read IPAddr: %w", err)
	}

	ipPort, data, err := readFlaggedString(flags, flagIPPort, data, "IPPort")
	if err != nil {
		return State{}, err
	}

	// Holds the hexadecimal text of the usual 16-byte nonce on the stack.
	var nonceScratch [32]byte

	nonce, data, err := readNonceField(version, flags, data, nonceScratch[:0])
	if err != nil {
		return State{}, fmt.Errorf("read Nonce: %w", err)
	}

	if len(data) != 0 {
		return State{}, fmt.Errorf("unexpected trailing state data: %d bytes", len(data))
	}

	setStateStrings(&state, sessionID, commonName, ipAddr, ipPort, nonce)

	return state, nil
}

// readFlaggedString reads the length-prefixed string field named name when
// flag is set in flags, and returns nil otherwise.
func readFlaggedString(flags, flag byte, data []byte, name string) ([]byte, []byte, error) {
	if flags&flag == 0 {
		return nil, data, nil
	}

	value, data, err := readStringBytes(data)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", name, err)
	}

	return value, data, nil
}

// readNonceField reads the nonce field in the encoding of the given state version.
func readNonceField(version, flags byte, data, scratch []byte) ([]byte, []byte, error) {
	switch {
	case flags&flagNonce == 0:
		return nil, data, nil
	case version == binaryStateVersionTextNonce:
		return readStringBytes(data)
	default:
		return readNonce(data, scratch)
	}
}

// readIPAddr reads the IP address field indicated by the state flags.
func readIPAddr(flags byte, data, scratch []byte) ([]byte, []byte, error) {
	switch {
	case flags&flagIPAddrV4 != 0:
		return readIPAddrV4(data, scratch)
	case flags&flagIPAddrV6 != 0:
		return readIPAddrV6(data, scratch)
	case flags&flagIPAddrText != 0:
		return readStringBytes(data)
	default:
		return nil, data, nil
	}
}

// setStateStrings stores all decoded string fields in one immutable backing string.
func setStateStrings(state *State, sessionID, commonName, ipAddr, ipPort, nonce []byte) {
	sessionIDEnd := len(sessionID)
	commonNameEnd := sessionIDEnd + len(commonName)
	ipAddrEnd := commonNameEnd + len(ipAddr)
	ipPortEnd := ipAddrEnd + len(ipPort)
	nonceEnd := ipPortEnd + len(nonce)

	var packedStrings string

	if nonceEnd <= stateStringScratchSize {
		var scratch [stateStringScratchSize]byte

		packed := scratch[:0]
		packed = append(packed, sessionID...)
		packed = append(packed, commonName...)
		packed = append(packed, ipAddr...)
		packed = append(packed, ipPort...)
		packed = append(packed, nonce...)
		packedStrings = string(packed)
	} else {
		var builder strings.Builder

		builder.Grow(nonceEnd)

		_, _ = builder.Write(sessionID)
		_, _ = builder.Write(commonName)
		_, _ = builder.Write(ipAddr)
		_, _ = builder.Write(ipPort)
		_, _ = builder.Write(nonce)

		packedStrings = builder.String()
	}

	state.Client.SessionID = packedStrings[:sessionIDEnd]
	state.Client.CommonName = packedStrings[sessionIDEnd:commonNameEnd]
	state.IPAddr = packedStrings[commonNameEnd:ipAddrEnd]
	state.IPPort = packedStrings[ipAddrEnd:ipPortEnd]
	state.Nonce = packedStrings[ipPortEnd:nonceEnd]
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

// readStringBytes reads a length-prefixed string from a binary state payload.
func readStringBytes(data []byte) ([]byte, []byte, error) {
	length, data, err := readUvarint(data)
	if err != nil {
		return nil, nil, err
	}

	if uint64(len(data)) < length {
		return nil, nil, fmt.Errorf("string length %d exceeds remaining data %d", length, len(data))
	}

	return data[:length], data[length:], nil
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
func readIPAddrV4(data, scratch []byte) ([]byte, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("ipv4 length exceeds remaining data %d", len(data))
	}

	var ipBytes [4]byte
	copy(ipBytes[:], data[:4])

	return netip.AddrFrom4(ipBytes).AppendTo(scratch), data[4:], nil
}

// readIPAddrV6 reads a raw 16-byte IPv6 address from a binary state payload.
func readIPAddrV6(data, scratch []byte) ([]byte, []byte, error) {
	if len(data) < 16 {
		return nil, nil, fmt.Errorf("ipv6 length exceeds remaining data %d", len(data))
	}

	var ipBytes [16]byte
	copy(ipBytes[:], data[:16])

	return netip.AddrFrom16(ipBytes).AppendTo(scratch), data[16:], nil
}

// boolToInt converts a boolean flag to the integer representation used by ClientIdentifier.
func boolToInt(value bool) int {
	if value {
		return 1
	}

	return 0
}
