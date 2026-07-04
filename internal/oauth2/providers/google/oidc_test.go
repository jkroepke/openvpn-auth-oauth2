package google_test

import (
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/stretchr/testify/require"
	gooauth2 "golang.org/x/oauth2"
)

func TestGetRefreshToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tokens      *idtoken.IDToken
		expected    string
		expectedErr error
	}{
		{
			name:        "missing tokens",
			expectedErr: oauth2.ErrMissingToken,
		},
		{
			name: "missing refresh token",
			tokens: &idtoken.IDToken{
				Token: &gooauth2.Token{},
			},
			expectedErr: oauth2.ErrNoRefreshToken,
		},
		{
			name: "refresh token",
			tokens: &idtoken.IDToken{
				Token: &gooauth2.Token{RefreshToken: "provider-refresh-token"},
			},
			expected: "provider-refresh-token",
		},
	}

	provider, err := google.NewProvider(t.Context(), new(config.Defaults), http.DefaultClient)
	require.NoError(t, err)

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			refreshToken, err := provider.GetRefreshToken(testCase.tokens)

			if testCase.expectedErr != nil {
				require.ErrorIs(t, err, testCase.expectedErr)
				require.Empty(t, refreshToken)

				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expected, refreshToken)
		})
	}
}
