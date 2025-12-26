package state

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

func Encrypt(data []byte, secretKey string) (string, error) {
	issued := time.Now().Round(time.Second).Unix()
	data = append([]byte(strconv.FormatInt(issued, 10)+" "), data...)

	encrypted, err := crypto.EncryptBytesAES(data, secretKey)
	if err != nil {
		return "", fmt.Errorf("encrypt aes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(encrypted), nil
}

func Decrypt(encodedState, secretKey string) ([]byte, error) {
	if err := checkTokenSize(encodedState); err != nil {
		return nil, err
	}

	encrypted, err := decodeBase64(encodedState)
	if err != nil {
		return nil, err
	}

	data, err := decryptAES(encrypted, secretKey, encodedState)
	if err != nil {
		return nil, err
	}

	issued, data, err := extractIssued(data)
	if err != nil {
		return nil, err
	}

	if err := validateIssued(issued); err != nil {
		return nil, err
	}

	return data, nil
}

// extractIssued extracts the issued timestamp from the decrypted data.
// The timestamp is stored as a string followed by a space at the beginning of the data.
func extractIssued(data []byte) (int64, []byte, error) {
	// Find the space separator
	spaceIdx := -1

	for i, b := range data {
		if b == ' ' {
			spaceIdx = i

			break
		}
	}

	if spaceIdx == -1 {
		return 0, nil, errors.New("invalid data format: no timestamp found")
	}

	// Parse the timestamp
	issued, err := strconv.ParseInt(string(data[:spaceIdx]), 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("parse issued timestamp: %w", err)
	}

	// Return the timestamp and the remaining data (after the space)
	return issued, data[spaceIdx+1:], nil
}
