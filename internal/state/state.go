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
	Cid        int    `json:"cid"`
	Kid        int    `json:"kid"`
	Ipaddr     string `json:"ipaddr"`
	CommonName string `json:"common_name"`

	Encoded string
}

func New(cid, kid int, ipaddr, commonName string) *State {
	return &State{
		Cid:        cid,
		Kid:        kid,
		Ipaddr:     ipaddr,
		CommonName: commonName,
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

	if err := json.Unmarshal(jsonState, &state); err != nil {
		return err
	}

	return nil
}

func (state *State) Encode(secretKey string) error {
	jsonState, err := json.Marshal(state)
	if err != nil {
		return err
	}

	state.Encoded, err = encrypt(jsonState, secretKey)
	if err != nil {
		return err
	}

	return nil
}

func encrypt(plaintext []byte, secretKey string) (string, error) {
	aesCipher, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aesCipher)
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
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(b64Ciphertext string, secretKey string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
