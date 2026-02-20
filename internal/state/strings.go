package state

import (
	"bytes"
	"slices"
	"strings"
)

// decodeStringBytes decodes OpenVPN state string fields.
// A single \x00 byte indicates an empty string; otherwise, all \x00 are replaced with spaces.
func decodeStringBytes(field []byte) string {
	// If input is exactly one byte and is '\x00', return ""
	if len(field) == 1 && field[0] == '\x00' {
		return ""
	}
	// Fast-path: if no \x00, return the string as-is with no allocation.
	if !slices.Contains(field, '\x00') {
		return string(field)
	}

	// Replace all \x00 bytes with spaces.
	out := make([]byte, len(field))

	for i := range field {
		if field[i] == '\x00' {
			out[i] = ' '
		} else {
			out[i] = field[i]
		}
	}

	return string(out)
}

// encodeStringToBuffer encodes a string field for OpenVPN state serialization.
// Empty strings are encoded as a single \x00 byte; spaces are replaced with \x00.
func encodeStringToBuffer(buf *bytes.Buffer, text string) {
	if text == "" {
		buf.WriteByte('\x00')

		return
	}

	// Fast-path: no spaces, write the entire string at once.
	if !strings.Contains(text, " ") {
		buf.WriteString(text)

		return
	}

	// Write chunks between spaces, replacing spaces with \x00.
	for {
		idx := strings.IndexByte(text, ' ')
		if idx == -1 {
			buf.WriteString(text)

			return
		}

		buf.WriteString(text[:idx])
		buf.WriteByte('\x00')

		text = text[idx+1:]
	}
}
