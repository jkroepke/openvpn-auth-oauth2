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
	CommonName string    `json:"common_name"`
	Issued     time.Time `json:"issued"`

	Encoded string
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

func NewEncoded(state string) *State {
	return &State{
		Encoded: state,
	}
}

func (state *State) Decode(secretKey string) error {
	jsonState, err := crypto.DecryptAES(state.Encoded, secretKey)
	if err != nil {
		return fmt.Errorf("invalid state: %v: %v", state.Encoded, err)
	}

	if err := json.Unmarshal([]byte(jsonState), &state); err != nil {
		return err
	}

	issuedSince := time.Since(state.Issued)

	if issuedSince >= time.Minute*2 {
		return fmt.Errorf("state expired after 2 minutes, issued at: %s", state.Issued.String())
	} else if issuedSince <= time.Second*-5 {
		return fmt.Errorf("state issued in future, issued at: %s", state.Issued.String())
	}

	return nil
}

func (state *State) Encode(secretKey string) error {
	jsonState, err := json.Marshal(state)
	if err != nil {
		return err
	}

	state.Encoded, err = crypto.EncryptAES(string(jsonState), secretKey)
	if err != nil {
		return err
	}

	return nil
}
