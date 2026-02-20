//nolint:testpackage
package state

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeStringBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "single null byte returns empty string",
			input:    []byte{'\x00'},
			expected: "",
		},
		{
			name:     "empty byte slice",
			input:    make([]byte, 0),
			expected: "",
		},
		{
			name:     "simple string without nulls",
			input:    []byte("hello"),
			expected: "hello",
		},
		{
			name:     "string with null replaced by space",
			input:    []byte("hello\x00world"),
			expected: "hello world",
		},
		{
			name:     "multiple nulls replaced by spaces",
			input:    []byte("one\x00two\x00three"),
			expected: "one two three",
		},
		{
			name:     "leading null",
			input:    []byte("\x00hello"),
			expected: " hello",
		},
		{
			name:     "trailing null",
			input:    []byte("hello\x00"),
			expected: "hello ",
		},
		{
			name:     "consecutive nulls",
			input:    []byte("a\x00\x00b"),
			expected: "a  b",
		},
		{
			name:     "only nulls (multiple)",
			input:    []byte("\x00\x00\x00"),
			expected: "   ",
		},
		{
			name:     "unicode characters",
			input:    []byte("héllo\x00wörld"),
			expected: "héllo wörld",
		},
		{
			name:     "common name with spaces",
			input:    []byte("John\x00Doe"),
			expected: "John Doe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := decodeStringBytes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEncodeStringToBuffer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "empty string encodes to single null",
			input:    "",
			expected: []byte{'\x00'},
		},
		{
			name:     "simple string without spaces",
			input:    "hello",
			expected: []byte("hello"),
		},
		{
			name:     "string with space replaced by null",
			input:    "hello world",
			expected: []byte("hello\x00world"),
		},
		{
			name:     "multiple spaces replaced by nulls",
			input:    "one two three",
			expected: []byte("one\x00two\x00three"),
		},
		{
			name:     "leading space",
			input:    " hello",
			expected: []byte("\x00hello"),
		},
		{
			name:     "trailing space",
			input:    "hello ",
			expected: []byte("hello\x00"),
		},
		{
			name:     "consecutive spaces",
			input:    "a  b",
			expected: []byte("a\x00\x00b"),
		},
		{
			name:     "only spaces",
			input:    "   ",
			expected: []byte("\x00\x00\x00"),
		},
		{
			name:     "unicode characters with space",
			input:    "héllo wörld",
			expected: []byte("héllo\x00wörld"),
		},
		{
			name:     "common name format",
			input:    "John Doe",
			expected: []byte("John\x00Doe"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			encodeStringToBuffer(&buf, tc.input)
			assert.Equal(t, tc.expected, buf.Bytes())
		})
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "empty string", input: ""},
		{name: "simple string", input: "hello"},
		{name: "string with spaces", input: "hello world"},
		{name: "multiple spaces", input: "one two three four"},
		{name: "unicode", input: "héllo wörld 日本語"}, //nolint:gosmopolitan
		{name: "common name", input: "John Doe"},
		{name: "IP address", input: "192.168.1.1"},
		{name: "path with spaces", input: "/path/to/some file.txt"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			encodeStringToBuffer(&buf, tc.input)
			decoded := decodeStringBytes(buf.Bytes())
			assert.Equal(t, tc.input, decoded)
		})
	}
}

func BenchmarkDecodeStringBytes(b *testing.B) {
	b.Run("no nulls", func(b *testing.B) {
		input := []byte("helloworldwithoutnulls")
		for b.Loop() {
			_ = decodeStringBytes(input)
		}

		b.ReportAllocs()
	})

	b.Run("with nulls", func(b *testing.B) {
		input := []byte("hello\x00world\x00with\x00nulls")
		for b.Loop() {
			_ = decodeStringBytes(input)
		}

		b.ReportAllocs()
	})

	b.Run("single null", func(b *testing.B) {
		input := []byte{'\x00'}
		for b.Loop() {
			_ = decodeStringBytes(input)
		}

		b.ReportAllocs()
	})
}

func BenchmarkEncodeStringToBuffer(b *testing.B) {
	b.Run("no spaces", func(b *testing.B) {
		input := "helloworldwithoutspaces"

		var buf bytes.Buffer
		for b.Loop() {
			buf.Reset()
			encodeStringToBuffer(&buf, input)
		}

		b.ReportAllocs()
	})

	b.Run("with spaces", func(b *testing.B) {
		input := "hello world with spaces"

		var buf bytes.Buffer
		for b.Loop() {
			buf.Reset()
			encodeStringToBuffer(&buf, input)
		}

		b.ReportAllocs()
	})

	b.Run("empty string", func(b *testing.B) {
		input := ""

		var buf bytes.Buffer
		for b.Loop() {
			buf.Reset()
			encodeStringToBuffer(&buf, input)
		}

		b.ReportAllocs()
	})
}
