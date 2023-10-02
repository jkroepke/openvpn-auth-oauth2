package state

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zitadel/oidc/v2/pkg/crypto"
)

type State struct {
	Cid        uint64    `json:"cid"`
	Kid        uint64    `json:"kid"`
	Ipaddr     string    `json:"ipaddr"`
	CommonName string    `json:"commonName"`
	Issued     time.Time `json:"issued"`

	encoded string
}

func New(cid, kid uint64, ipaddr, commonName string) *State {
	return &State{
		Cid:        cid,
		Kid:        kid,
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
