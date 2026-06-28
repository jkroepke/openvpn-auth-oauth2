package types_test

import (
	"encoding/json"
	"os"
	"path"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretString(t *testing.T) {
	t.Parallel()

	secret := types.Secret("SECRET")

	assert.Equal(t, "SECRET", secret.String())
}

func TestSecretMarshalText(t *testing.T) {
	t.Parallel()

	secret, err := types.Secret("SECRET").MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("SECRET"), secret)
}

func TestSecretUnmarshalText(t *testing.T) {
	t.Parallel()

	var secret types.Secret

	require.NoError(t, secret.UnmarshalText([]byte("SECRET")))
	assert.Equal(t, types.Secret("SECRET"), secret)
}

func TestSecretUnmarshalTextFile(t *testing.T) {
	t.Parallel()

	var secret types.Secret

	filePath := path.Join(t.TempDir(), "test.file")

	require.NoError(t, os.WriteFile(filePath, []byte("SECRET"), 0o600))
	require.NoError(t, secret.UnmarshalText([]byte("file://"+filePath)))
	assert.Equal(t, types.Secret("SECRET"), secret)
}

func TestSecretMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		secret   types.Secret
		expected string
	}{
		{
			name:     "empty",
			expected: `""`,
		},
		{
			name:     "redacted",
			secret:   types.Secret("SECRET"),
			expected: `"***"`,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			body, err := json.Marshal(testCase.secret)

			require.NoError(t, err)
			assert.JSONEq(t, testCase.expected, string(body))
		})
	}
}
