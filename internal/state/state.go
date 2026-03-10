package state

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/crypto"
)

const numFields = 8

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

// Encrypt serializes the state into a space-separated, Salsa20-encrypted, base64-URL-safe string.
// Fields are encoded in fixed order:
//
//	CID KID SessionID UsernameIsDefined CommonName IPAddr IPPort SessionState
//
// Empty strings are encoded as \x00, and spaces as \x00.
// The result is safe for use in URL parameters and has a ~1-second resolution timestamp.
func Encrypt(cipher *crypto.Cipher, state State) (EncryptedState, error) {
	if cipher == nil {
		return "", errors.New("cipher is required")
	}

	var data bytes.Buffer
	// Preallocate buffer space to minimize reallocations.
	data.Grow(118 +
		len(state.Client.SessionID) +
		len(state.Client.CommonName) +
		len(state.IPAddr) +
		len(state.IPPort))

	var scratch [20]byte // Scratch buffer for integer conversions

	// write each field in order, separated by spaces.
	data.Write(strconv.AppendUint(scratch[:0], state.Client.CID, 10))
	data.WriteByte(' ')
	data.Write(strconv.AppendUint(scratch[:0], state.Client.KID, 10))
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
	data.WriteString("\n")

	encrypted, err := cipher.EncryptBytesWithTime(data.Bytes())
	if err != nil {
		return "", fmt.Errorf("encrypt state: %w", err)
	}

	return EncryptedState(encrypted), nil
}

func Decrypt(cipher *crypto.Cipher, encryptedState EncryptedState) (State, error) {
	if cipher == nil {
		return State{}, errors.New("cipher is required")
	}

	data, err := cipher.DecryptBytesWithTime([]byte(encryptedState))
	if err != nil {
		return State{}, fmt.Errorf("decrypt state: %w", err)
	}

	fields, err := splitStateFields(data)
	if err != nil {
		return State{}, err
	}

	return parseStateFields(fields)
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
func parseStateFields(fields [][]byte) (State, error) {
	cid, err := strconv.ParseUint(string(fields[0]), 10, 64)
	if err != nil {
		return State{}, fmt.Errorf("parse CID: %w", err)
	}

	kid, err := strconv.ParseUint(string(fields[1]), 10, 64)
	if err != nil {
		return State{}, fmt.Errorf("parse KID: %w", err)
	}

	usernameIsDefined, err := strconv.Atoi(string(fields[3]))
	if err != nil {
		return State{}, fmt.Errorf("parse UsernameIsDefined: %w", err)
	}

	state := State{
		Client: ClientIdentifier{
			CID:               cid,
			KID:               kid,
			SessionID:         decodeStringBytes(fields[2]),
			UsernameIsDefined: usernameIsDefined,
			CommonName:        decodeStringBytes(fields[4]),
		},
		IPAddr:       string(fields[5]),
		IPPort:       string(fields[6]),
		SessionState: decodeSessionState(string(fields[7])),
	}

	return state, nil
}
