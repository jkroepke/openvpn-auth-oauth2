package state

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

const numFields = 13

// State represents the context and security information associated with an OAuth2 login flow.
//
// The `State` value is passed to the `state` GET parameter during the OAuth2 login flow.
// It ensures that the client initiating the login flow is the same client completing it,
// thus preventing CSRF (Cross-Site Request Forgery) attacks. The `State` value is returned
// by the OAuth2 Identity Provider (IDP) in the redirect URL.
//
// To prevent tampering, the `State` is protected using AES encryption.
type State struct {
	IPAddr       string           // Client's IP address
	IPPort       string           // Client's port
	SessionState string           // Compact session state representation
	Client       ClientIdentifier // Information about the client
	ServerName   string           // OpenVPN server name
	Issued       int64            // Timestamp (seconds since Unix epoch)
}

// ClientIdentifier holds detailed information about the client initiating an OAuth2 login flow.
//
// This struct provides more context for the client and can be passed to [github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn.Client.AcceptClient].
type ClientIdentifier struct {
	SessionID            string // OpenVPN session identifier
	CommonName           string // OpenVPN common name (user)
	AuthFailedReasonFile string // File for failed authentication reasons
	AuthControlFile      string // Control file for authentication
	CID                  uint64 // OpenVPN connection ID
	KID                  uint64 // OpenVPN key ID
	UsernameIsDefined    int    // 1 if username is defined, 0 otherwise
}

// New returns a new State with the current timestamp (rounded to the nearest second).
func New(client ClientIdentifier, ipAddr, ipPort, sessionState, serverName string) State {
	return State{
		Client:       client,
		IPAddr:       ipAddr,
		IPPort:       ipPort,
		SessionState: sessionState,
		ServerName:   serverName,
		Issued:       time.Now().Round(time.Second).Unix(),
	}
}

// NewWithEncodedToken creates a State from an encoded and encrypted token.
func NewWithEncodedToken(encodedState, secretKey string) (State, error) {
	var state State

	if err := state.decode(encodedState, secretKey); err != nil {
		return state, err
	}

	return state, nil
}

// Encode serializes the state into a space-separated, AES-encrypted, base64-URL-safe string.
// Fields are encoded in fixed order:
//
//	CID KID AuthFailedReasonFile AuthControlFile SessionID UsernameIsDefined CommonName IPAddr IPPort SessionState Issued
//
// Empty strings are encoded as \x00, and spaces as \x00.
// The result is safe for use in URL parameters and has a ~1-second resolution timestamp.
func (state *State) Encode(secretKey string) (string, error) {
	var data bytes.Buffer
	// Preallocate buffer space to minimize reallocations.
	data.Grow(129 +
		len(state.Client.AuthFailedReasonFile) +
		len(state.Client.AuthControlFile) +
		len(state.Client.SessionID) +
		len(state.Client.CommonName) +
		len(state.IPAddr) +
		len(state.IPPort) +
		len(state.ServerName))

	var scratch [20]byte // Scratch buffer for integer conversions

	// Write each field in order, separated by spaces.
	data.WriteString(secretKey[0:2])
	data.WriteByte(' ')
	data.Write(strconv.AppendUint(scratch[:0], state.Client.CID, 10))
	data.WriteByte(' ')
	data.Write(strconv.AppendUint(scratch[:0], state.Client.KID, 10))
	data.WriteByte(' ')
	encodeStringToBuffer(&data, state.Client.AuthFailedReasonFile)
	data.WriteByte(' ')
	encodeStringToBuffer(&data, state.Client.AuthControlFile)
	data.WriteByte(' ')
	encodeStringToBuffer(&data, state.Client.SessionID)
	data.WriteByte(' ')
	data.Write(strconv.AppendInt(scratch[:0], int64(state.Client.UsernameIsDefined), 10))
	data.WriteByte(' ')
	encodeStringToBuffer(&data, state.Client.CommonName)
	data.WriteByte(' ')
	encodeStringToBuffer(&data, state.IPAddr)
	data.WriteByte(' ')
	encodeStringToBuffer(&data, state.IPPort)
	data.WriteByte(' ')
	data.WriteString(encodeSessionState(state.SessionState))
	data.WriteByte(' ')
	encodeStringToBuffer(&data, state.ServerName)
	data.WriteByte(' ')
	data.Write(strconv.AppendInt(scratch[:0], state.Issued, 10))
	data.WriteString("\r\n")

	// Encrypt the buffer using AES and encode the result as base64 URL-safe.
	encrypted, err := crypto.EncryptBytesAES(data.Bytes(), secretKey)
	if err != nil {
		return "", fmt.Errorf("encrypt aes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// decode parses and decrypts a state string, populating the State struct fields.
// Returns an error if the token is invalid, expired, or otherwise corrupt.
func (state *State) decode(encodedState, secretKey string) error {
	if err := checkTokenSize(encodedState); err != nil {
		return err
	}

	encrypted, err := decodeBase64(encodedState)
	if err != nil {
		return err
	}

	data, err := decryptAES(encrypted, secretKey, encodedState)
	if err != nil {
		return err
	}

	fields, err := splitStateFields(data)
	if err != nil {
		return err
	}

	if len(fields[0]) < 2 || !bytes.Equal(fields[0], []byte(secretKey[:2])) {
		return fmt.Errorf("expected secret key prefix %s, got %s", secretKey[:2], string(fields[0]))
	}

	if err := parseStateFields(state, fields); err != nil {
		return err
	}

	return validateIssued(state.Issued)
}

// Helper to check token size.
func checkTokenSize(encodedState string) error {
	if len(encodedState) > 1024 {
		return fmt.Errorf("%w: token too large", ErrInvalid)
	}

	return nil
}

// Helper to decode base64.
func decodeBase64(encodedState string) ([]byte, error) {
	encrypted, err := base64.URLEncoding.DecodeString(encodedState)
	if err != nil {
		return nil, fmt.Errorf("base64 decode %s: %w", encodedState, err)
	}

	return encrypted, nil
}

// Helper to decrypt AES.
func decryptAES(encrypted []byte, secretKey, encodedState string) ([]byte, error) {
	data, err := crypto.DecryptBytesAES(encrypted, secretKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt aes %s: %w", encodedState, err)
	}

	return data, nil
}

// Helper to split fields and check field count.
func splitStateFields(data []byte) ([][]byte, error) {
	fields := bytes.Fields(data)
	if len(fields) != numFields {
		return nil, fmt.Errorf("expected %d fields, got %d: %q", numFields, len(fields), data)
	}

	return fields, nil
}

// Helper to parse all fields into the State struct.
func parseStateFields(state *State, fields [][]byte) error {
	var err error
	if state.Client.CID, err = strconv.ParseUint(string(fields[1]), 10, 64); err != nil {
		return fmt.Errorf("parse CID: %w", err)
	}

	if state.Client.KID, err = strconv.ParseUint(string(fields[2]), 10, 64); err != nil {
		return fmt.Errorf("parse KID: %w", err)
	}

	state.Client.AuthFailedReasonFile = decodeStringBytes(fields[3])
	state.Client.AuthControlFile = decodeStringBytes(fields[4])
	state.Client.SessionID = decodeStringBytes(fields[5])

	if state.Client.UsernameIsDefined, err = strconv.Atoi(string(fields[6])); err != nil {
		return fmt.Errorf("parse UsernameIsDefined: %w", err)
	}

	state.Client.CommonName = decodeStringBytes(fields[7])
	state.IPAddr = string(fields[8])
	state.IPPort = string(fields[9])
	state.SessionState = decodeSessionState(string(fields[10]))
	state.ServerName = decodeStringBytes(fields[11])

	if state.Issued, err = strconv.ParseInt(string(fields[12]), 10, 64); err != nil {
		return fmt.Errorf("parse Issued: %w", err)
	}

	return nil
}

// validateIssued the issued timestamp.
func validateIssued(issued int64) error {
	issuedSince := time.Since(time.Unix(issued, 0))

	if issuedSince >= time.Minute*2 {
		return fmt.Errorf("%w: expired after 2 minutes, issued at: %s", ErrInvalid, issuedSince.String())
	}

	if issuedSince <= time.Second*-5 {
		return fmt.Errorf("%w: issued in future, issued at: %s", ErrInvalid, issuedSince.String())
	}

	return nil
}

// decodeStringBytes decodes OpenVPN state string fields.
// A single \x00 byte indicates an empty string; otherwise, all \x00 are replaced with spaces.
func decodeStringBytes(field []byte) string {
	// If input is exactly one byte and is '\x00', return ""
	if len(field) == 1 && field[0] == '\x00' {
		return ""
	}
	// Fast-path: if no \x00, return the string as-is with no allocation.
	needReplace := false

	for _, c := range field {
		if c == '\x00' {
			needReplace = true

			break
		}
	}

	if !needReplace {
		return string(field)
	}

	// Replace all \x00 bytes with spaces.
	out := make([]byte, len(field))

	for i := range field {
		if field[i] == '\x00' {
			out[i] = ' '
		} else {
			out[i] = field[i]
		}
	}

	return string(out)
}

// encodeStringToBuffer encodes a string field for OpenVPN state serialization.
// Empty strings are encoded as a single \x00 byte; spaces are replaced with \x00.
func encodeStringToBuffer(buf *bytes.Buffer, text string) {
	if text == "" {
		buf.WriteByte('\x00')

		return
	}

	for _, b := range text {
		if b == ' ' {
			buf.WriteByte('\x00')
		} else {
			buf.WriteByte(byte(b))
		}
	}
}
