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
	Ipaddr     string
	CommonName string
	Issued     int64

	encoded string
}

type ClientIdentifier struct {
	Cid                  uint64
	Kid                  uint64
	AuthFailedReasonFile string
	AuthControlFile      string
	AuthToken            string
}

func New(client ClientIdentifier, ipaddr, commonName string) State {
	return State{
		Client:     client,
		Ipaddr:     ipaddr,
		CommonName: commonName,
		Issued:     time.Now().Round(time.Second).Unix(),
	}
}

func NewEncoded(state string) State {
	return State{
		encoded: state,
	}
}

func (state *State) Encoded() string {
	return state.encoded
}

func (state *State) Decode(secretKey string) error {
	encrypted, err := base64.RawURLEncoding.DecodeString(state.encoded)
	if err != nil {
		return fmt.Errorf("base64 decode %s: %w", state.encoded, err)
	}

	data, err := crypto.DecryptBytesAES(encrypted, secretKey)
	if err != nil {
		return fmt.Errorf("decrypt aes %s: %w", state.encoded, err)
	}

	_, err = fmt.Fscanln(bytes.NewReader(data),
		&state.Client.Cid,
		&state.Client.Kid,
		&state.Client.AuthFailedReasonFile,
		&state.Client.AuthControlFile,
		&state.Ipaddr,
		&state.CommonName,
		&state.Issued,
	)
	if err != nil {
		return fmt.Errorf("scan error %#v: %w", string(data), err)
	}

	state.Client.AuthFailedReasonFile = decodeString(state.Client.AuthFailedReasonFile)
	state.Client.AuthControlFile = decodeString(state.Client.AuthControlFile)
	state.CommonName = decodeString(state.CommonName)

	issuedSince := time.Since(time.Unix(state.Issued, 0))

	if issuedSince >= time.Minute*2 {
		return fmt.Errorf("%w: expired after 2 minutes, issued at: %s", ErrInvalid, issuedSince.String())
	} else if issuedSince <= time.Second*-5 {
		return fmt.Errorf("%w: issued in future, issued at: %s", ErrInvalid, issuedSince.String())
	}

	return nil
}

func (state *State) Encode(secretKey string) error {
	var data bytes.Buffer

	data.Grow(512)
	data.WriteString(strconv.FormatUint(state.Client.Cid, 10))
	data.WriteString(" ")
	data.WriteString(strconv.FormatUint(state.Client.Kid, 10))
	data.WriteString(" ")
	data.WriteString(encodeString(state.Client.AuthFailedReasonFile))
	data.WriteString(" ")
	data.WriteString(encodeString(state.Client.AuthControlFile))
	data.WriteString(" ")
	data.WriteString(state.Ipaddr)
	data.WriteString(" ")
	data.WriteString(encodeString(state.CommonName))
	data.WriteString(" ")
	data.WriteString(strconv.FormatInt(state.Issued, 10))
	data.WriteString("\n")

	encrypted, err := crypto.EncryptBytesAES(data.Bytes(), secretKey)
	if err != nil {
		return fmt.Errorf("encrypt aes: %w", err)
	}

	state.encoded = base64.RawURLEncoding.EncodeToString(encrypted)

	return nil
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
