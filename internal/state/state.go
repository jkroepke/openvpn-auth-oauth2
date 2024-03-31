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

type State struct {
	Client     ClientIdentifier
	IPAddr     string
	IPPort     string
	CommonName string
	Issued     int64
}

type ClientIdentifier struct {
	CID                  uint64
	KID                  uint64
	SessionID            string
	AuthFailedReasonFile string
	AuthControlFile      string
}

func New(client ClientIdentifier, ipAddr, ipPort, commonName string) State {
	return State{
		Client:     client,
		IPAddr:     ipAddr,
		IPPort:     ipPort,
		CommonName: commonName,
		Issued:     time.Now().Round(time.Second).Unix(),
	}
}

func NewWithEncodedToken(encodedState, secretKey string) (State, error) {
	state := State{}

	if err := state.decode(encodedState, secretKey); err != nil {
		return State{}, err
	}

	return state, nil
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
		&state.IPAddr,
		&state.IPPort,
		&state.CommonName,
		&state.Issued,
	)
	if err != nil {
		return fmt.Errorf("scan error %#v: %w", string(data), err)
	}

	state.Client.AuthFailedReasonFile = decodeString(state.Client.AuthFailedReasonFile)
	state.Client.AuthControlFile = decodeString(state.Client.AuthControlFile)
	state.Client.SessionID = decodeString(state.Client.SessionID)
	state.IPAddr = decodeString(state.IPAddr)
	state.IPPort = decodeString(state.IPPort)
	state.CommonName = decodeString(state.CommonName)

	issuedSince := time.Since(time.Unix(state.Issued, 0))

	if issuedSince >= time.Minute*2 {
		return fmt.Errorf("%w: expired after 2 minutes, issued at: %s", ErrInvalid, issuedSince.String())
	} else if issuedSince <= time.Second*-5 {
		return fmt.Errorf("%w: issued in future, issued at: %s", ErrInvalid, issuedSince.String())
	}

	return nil
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
	data.WriteString(encodeString(state.IPAddr))
	data.WriteString(" ")
	data.WriteString(encodeString(state.IPPort))
	data.WriteString(" ")
	data.WriteString(encodeString(state.CommonName))
	data.WriteString(" ")
	data.WriteString(strconv.FormatInt(state.Issued, 10))
	data.WriteString("\r\n")

	encrypted, err := crypto.EncryptBytesAES(data.Bytes(), secretKey)
	if err != nil {
		return "", fmt.Errorf("encrypt aes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func encodeString(text string) string {
	if text == "" {
		return "\x00"
	}

	return strings.ReplaceAll(text, " ", "\x00")
}

func decodeString(text string) string {
	if text == "\x00" {
		return ""
	}

	return strings.ReplaceAll(text, "\x00", " ")
}
