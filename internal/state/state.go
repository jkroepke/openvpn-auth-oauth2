package state

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type State struct {
	Cid    int    `json:"cid"`
	Kid    int    `json:"kid"`
	Ipaddr string `json:"ipaddr"`

	Encoded string
}

func New(cid, kid int, ipaddr string) *State {
	return &State{
		Cid:    cid,
		Kid:    kid,
		Ipaddr: ipaddr,
	}
}

func NewEncoded(string string) *State {
	return &State{
		Encoded: string,
	}
}

func (state *State) Decode(secretKey string) error {
	jsonState, err := decrypt(state.Encoded, secretKey)
	if err != nil {
		return fmt.Errorf("invalid state: %v", state.Encoded)
	}

	if err := json.Unmarshal([]byte(jsonState), &state); err != nil {
		return err
	}

	return nil
}

func (state *State) Encode(secretKey string) error {
	jsonState, err := json.Marshal(state)
	if err != nil {
		return err
	}

	encrypted, err := encrypt(string(jsonState), secretKey)
	if err != nil {
		return err
	}

	state.Encoded = encrypted

	return nil
}

func encrypt(plaintext, secretKey string) (string, error) {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(b64Ciphertext, secretKey string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return "", err
	}

	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
