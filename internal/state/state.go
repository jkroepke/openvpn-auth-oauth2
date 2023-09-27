package state

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
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
		return errors.New(utils.StringConcat("invalid state: ", state.Encoded, ": ", err.Error()))
	}

	if err := json.Unmarshal([]byte(jsonState), &state); err != nil {
		return err
	}

	issuedSince := time.Since(state.Issued)

	if issuedSince >= time.Minute*2 {
		return errors.New(utils.StringConcat("state expired after 2 minutes, issued at: ", state.Issued.String()))
	} else if issuedSince <= time.Second*-5 {
		return errors.New(utils.StringConcat("state issued in future, issued at: ", state.Issued.String()))
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
