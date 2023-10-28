package state

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

type State struct {
	Client     ClientIdentifier `json:"c"`
	Ipaddr     string           `json:"ip"`
	CommonName string           `json:"cn"`
	Issued     time.Time        `json:"iss"`

	encoded string
}

type ClientIdentifier struct {
	Cid                  uint64 `json:"c"`
	Kid                  uint64 `json:"k"`
	AuthFailedReasonFile string `json:"afr"`
	AuthControlFile      string `json:"ac"`
}

func New(client ClientIdentifier, ipaddr, commonName string) *State {
	return &State{
		Client:     client,
		Ipaddr:     ipaddr,
		CommonName: commonName,
		Issued:     time.Now(),
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
	jsonState, err := crypto.DecryptAES(state.encoded, secretKey)
	if err != nil {
		return fmt.Errorf("invalid state %s: %w", state.encoded, err)
	}

	if err := json.Unmarshal([]byte(jsonState), &state); err != nil {
		return fmt.Errorf("json decode: %w", err)
	}

	issuedSince := time.Since(state.Issued)

	if issuedSince >= time.Minute*2 {
		return fmt.Errorf("%w: expired after 2 minutes, issued at: %s", ErrInvalid, state.Issued.String())
	} else if issuedSince <= time.Second*-5 {
		return fmt.Errorf("%w: issued in future, issued at: %s", ErrInvalid, state.Issued.String())
	}

	return nil
}

func (state *State) Encode(secretKey string) error {
	jsonState, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("json encode: %w", err)
	}

	state.encoded, err = crypto.EncryptAES(string(jsonState), secretKey)
	if err != nil {
		return fmt.Errorf("encrypt aes: %w", err)
	}

	return nil
}
