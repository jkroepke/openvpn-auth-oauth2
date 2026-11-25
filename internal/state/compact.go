package state

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

// String fields are stored with a uvarint header that holds the stored byte
// length shifted left by compactKindBits, and the encoding kind in the low
// bits. Values that OpenVPN and the OIDC flow commonly produce are stored in
// binary form, because every byte of the state costs about 1.33 characters of
// the 256-character OpenVPN WEB_AUTH parameter:
//
//   - decimal numbers, such as tls_serial_0 or a port, as a big-endian integer
//   - lowercase hexadecimal, such as the OIDC nonce, as raw bytes
//   - colon-separated lowercase hexadecimal, such as tls_digest_0, as raw bytes
//
// Anything else is stored as text.
const (
	compactKindText = iota
	compactKindDecimal
	compactKindHex
	compactKindColonHex

	compactKindBits = 2
	compactKindMask = 1<<compactKindBits - 1
)

// appendCompactString appends text in the smallest of the encodings above.
func appendCompactString(data []byte, text string) []byte {
	switch {
	case isCanonicalDecimal(text):
		var number big.Int

		number.SetString(text, 10)

		raw := number.Bytes()
		data = appendUvarint(data, uint64(len(raw))<<compactKindBits|compactKindDecimal)

		return append(data, raw...)
	case isLowerHex(text):
		data = appendUvarint(data, uint64(len(text)/2)<<compactKindBits|compactKindHex)

		// isLowerHex guarantees valid input, so decoding cannot fail.
		data, _ = hex.AppendDecode(data, []byte(text))

		return data
	case isColonHex(text):
		data = appendUvarint(data, uint64((len(text)+1)/3)<<compactKindBits|compactKindColonHex)

		for i := 0; i < len(text); i += 3 {
			data = append(data, hexNibble(text[i])<<4|hexNibble(text[i+1]))
		}

		return data
	default:
		data = appendUvarint(data, uint64(len(text))<<compactKindBits|compactKindText)

		return append(data, text...)
	}
}

// readCompactString reads a field written by appendCompactString, appends its
// text to dst and returns dst and the remaining payload.
func readCompactString(data, dst []byte) ([]byte, []byte, error) {
	header, data, err := readUvarint(data)
	if err != nil {
		return nil, nil, err
	}

	length := header >> compactKindBits

	if uint64(len(data)) < length {
		return nil, nil, fmt.Errorf("string length %d exceeds remaining data %d", length, len(data))
	}

	value, data := data[:length], data[length:]

	switch header & compactKindMask {
	case compactKindDecimal:
		var number big.Int

		dst = number.SetBytes(value).Append(dst, 10)
	case compactKindHex:
		dst = hex.AppendEncode(dst, value)
	case compactKindColonHex:
		for i, b := range value {
			if i > 0 {
				dst = append(dst, ':')
			}

			dst = hex.AppendEncode(dst, []byte{b})
		}
	default:
		dst = append(dst, value...)
	}

	return dst, data, nil
}

// isCanonicalDecimal reports whether text is a decimal number without leading zeros.
func isCanonicalDecimal(text string) bool {
	if text == "" || (text[0] == '0' && len(text) > 1) {
		return false
	}

	for i := range len(text) {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}

	return true
}

// isLowerHex reports whether text is a non-empty, even-length, lowercase hexadecimal string.
func isLowerHex(text string) bool {
	if text == "" || len(text)%2 != 0 {
		return false
	}

	for i := range len(text) {
		if !isLowerHexDigit(text[i]) {
			return false
		}
	}

	return true
}

// isColonHex reports whether text has the form "xx:xx:...:xx" with lowercase hexadecimal digits.
func isColonHex(text string) bool {
	if len(text) < 2 || (len(text)+1)%3 != 0 {
		return false
	}

	for i := range len(text) {
		if i%3 == 2 {
			if text[i] != ':' {
				return false
			}
		} else if !isLowerHexDigit(text[i]) {
			return false
		}
	}

	return true
}

func isLowerHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// hexNibble converts a lowercase hexadecimal digit to its value.
func hexNibble(c byte) byte {
	if c <= '9' {
		return c - '0'
	}

	return c - 'a' + 10
}
