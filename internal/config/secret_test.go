package config_test

import (
	"os"
	"path"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretString(t *testing.T) {
	t.Parallel()

	secret := config.Secret("SECRET")

	assert.Equal(t, "SECRET", secret.String())
}

func TestSecretMarshalText(t *testing.T) {
	t.Parallel()

	secret, err := config.Secret("SECRET").MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("SECRET"), secret)
}

func TestSecretUnmarshalText(t *testing.T) {
	t.Parallel()

	var secret config.Secret

	require.NoError(t, secret.UnmarshalText([]byte("SECRET")))
	assert.Equal(t, config.Secret("SECRET"), secret)
}

func TestSecretUnmarshalTextFile(t *testing.T) {
	t.Parallel()

	var secret config.Secret

	filePath := path.Join(t.TempDir(), "test.file")

	require.NoError(t, os.WriteFile(filePath, []byte("SECRET"), 0666))
	require.NoError(t, secret.UnmarshalText([]byte("file://"+filePath)))
	assert.Equal(t, config.Secret("SECRET"), secret)
}
