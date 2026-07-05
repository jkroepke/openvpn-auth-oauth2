package providers_test

import (
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers/google"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		providerName string
		expectedName string
		expectedErr  string
	}{
		{
			name:         "generic provider",
			providerName: generic.Name,
			expectedName: generic.Name,
		},
		{
			name:         "github provider",
			providerName: github.Name,
			expectedName: github.Name,
		},
		{
			name:         "google provider",
			providerName: google.Name,
			expectedName: google.Name,
		},
		{
			name:         "unknown provider",
			providerName: "unknown",
			expectedErr:  "unknown oauth2 provider: unknown",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			conf := config.Defaults
			conf.OAuth2.Provider = testCase.providerName

			provider, err := providers.New(t.Context(), &conf, http.DefaultClient)

			if testCase.expectedErr != "" {
				require.EqualError(t, err, testCase.expectedErr)
				require.Nil(t, provider)

				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expectedName, provider.GetName())
		})
	}
}
