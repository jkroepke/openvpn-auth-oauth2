package config_test

import (
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
	secret, err := config.Secret("SECRET").MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("SECRET"), secret)
}

func TestSecretUnmarshalText(t *testing.T) {
	var secret config.Secret
	require.NoError(t, secret.UnmarshalText([]byte("SECRET")))

	assert.Equal(t, config.Secret("SECRET"), secret)
}

func TestSecretUnmarshalTextFile(t *testing.T) {
	var secret config.Secret
	err := secret.UnmarshalText([]byte("file:///nonexists"))

	require.Error(t, err)
	assert.Equal(t, "unable read secret: open /nonexists: no such file or directory", err.Error())
}
