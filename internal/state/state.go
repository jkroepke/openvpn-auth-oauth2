package state

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

// State represents the context and security information associated with an OAuth2 login flow.
//
// The `State` value is passed to the `state` GET parameter during the OAuth2 login flow.
// It ensures that the client initiating the login flow is the same client completing it,
// thus preventing CSRF (Cross-Site Request Forgery) attacks. The `State` value is returned
// by the OAuth2 Identity Provider (IDP) in the redirect URL.
//
// To prevent tampering, the `State` is protected using AES encryption.
type State struct {
	Client       ClientIdentifier // Detailed information about the client initiating the flow.
	IPAddr       string           // IP address of the client.
	IPPort       string           // Port used by the client.
	SessionState string           // Session identifier for tracking the login state.
	Issued       int64            // Timestamp when the state was created.
}

// ClientIdentifier holds detailed information about the client initiating an OAuth2 login flow.
//
// This struct provides more context for the client and can be passed to [github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn.Client.AcceptClient].
type ClientIdentifier struct {
	CID                  uint64 // Unique identifier for the client.
	KID                  uint64 // Identifier for cryptographic keys.
	SessionID            string // Unique session identifier.
	CommonName           string // Human-readable name for the client.
	UsernameIsDefined    int    // Flag indicating if the username is defined.
	AuthFailedReasonFile string // Path or reference explaining authentication failure reasons.
	AuthControlFile      string // Path or reference for authentication control settings.
}

// New returns a new State.
func New(client ClientIdentifier, ipAddr, ipPort, sessionState string) State {
	return State{
		Client:       client,
		IPAddr:       ipAddr,
		IPPort:       ipPort,
		SessionState: sessionState,
		Issued:       time.Now().Round(time.Second).Unix(),
	}
}

func NewWithEncodedToken(encodedState, secretKey string) (State, error) {
	state := State{}

	if err := state.decode(encodedState, secretKey); err != nil {
		return State{}, err
	}

	return state, nil
}

func (state *State) Encode(secretKey string) (string, error) {
	var data bytes.Buffer

	data.Grow(512)
	data.WriteString(strconv.FormatUint(state.Client.CID, 10))
	data.WriteString(" ")
	data.WriteString(strconv.FormatUint(state.Client.KID, 10))
	data.WriteString(" ")
	data.WriteString(encodeString(state.Client.AuthFailedReasonFile))
	data.WriteString(" ")
	data.WriteString(encodeString(state.Client.AuthControlFile))
	data.WriteString(" ")
	data.WriteString(encodeString(state.Client.SessionID))
	data.WriteString(" ")
	data.WriteString(strconv.Itoa(state.Client.UsernameIsDefined))
	data.WriteString(" ")
	data.WriteString(encodeString(state.Client.CommonName))
	data.WriteString(" ")
	data.WriteString(encodeString(state.IPAddr))
	data.WriteString(" ")
	data.WriteString(encodeString(state.IPPort))
	data.WriteString(" ")
	data.WriteString(encodeSessionState(state.SessionState))
	data.WriteString(" ")
	data.WriteString(strconv.FormatInt(state.Issued, 10))
	data.WriteString("\r\n")

	encrypted, err := crypto.EncryptBytesAES(data.Bytes(), secretKey)
	if err != nil {
		return "", fmt.Errorf("encrypt aes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func (state *State) decode(encodedState, secretKey string) error {
	encrypted, err := base64.RawURLEncoding.DecodeString(encodedState)
	if err != nil {
		return fmt.Errorf("base64 decode %s: %w", encodedState, err)
	}

	data, err := crypto.DecryptBytesAES(encrypted, secretKey)
	if err != nil {
		return fmt.Errorf("decrypt aes %s: %w", encodedState, err)
	}

	_, err = fmt.Fscanln(bytes.NewReader(data),
		&state.Client.CID,
		&state.Client.KID,
		&state.Client.AuthFailedReasonFile,
		&state.Client.AuthControlFile,
		&state.Client.SessionID,
		&state.Client.UsernameIsDefined,
		&state.Client.CommonName,
		&state.IPAddr,
		&state.IPPort,
		&state.SessionState,
		&state.Issued,
	)
	if err != nil {
		return fmt.Errorf("scan error %#v: %w", string(data), err)
	}

	state.Client.AuthFailedReasonFile = decodeString(state.Client.AuthFailedReasonFile)
	state.Client.AuthControlFile = decodeString(state.Client.AuthControlFile)
	state.Client.SessionID = decodeString(state.Client.SessionID)
	state.Client.CommonName = decodeString(state.Client.CommonName)
	state.IPAddr = decodeString(state.IPAddr)
	state.IPPort = decodeString(state.IPPort)
	state.SessionState = decodeSessionState(state.SessionState)

	issuedSince := time.Since(time.Unix(state.Issued, 0))

	if issuedSince >= time.Minute*2 {
		return fmt.Errorf("%w: expired after 2 minutes, issued at: %s", ErrInvalid, issuedSince.String())
	} else if issuedSince <= time.Second*-5 {
		return fmt.Errorf("%w: issued in future, issued at: %s", ErrInvalid, issuedSince.String())
	}

	return nil
}

func decodeString(text string) string {
	if text == "\x00" {
		return ""
	}

	return strings.ReplaceAll(text, "\x00", " ")
}

func encodeString(text string) string {
	if text == "" {
		return "\x00"
	}

	return strings.ReplaceAll(text, " ", "\x00")
}
