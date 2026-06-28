package github_test

import (
	"log/slog"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
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
			name: "access token",
			tokens: &idtoken.IDToken{
				Token: &gooauth2.Token{AccessToken: "github-access-token"},
			},
			expected: "github-access-token",
		},
		{
			name: "empty access token",
			tokens: &idtoken.IDToken{
				Token: &gooauth2.Token{},
			},
		},
	}

	var provider github.Provider

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

func TestRefresh(t *testing.T) {
	t.Parallel()

	var provider github.Provider

	tokens, err := provider.Refresh(t.Context(), slog.New(slog.DiscardHandler), nil, "github-access-token")

	require.NoError(t, err)
	require.Equal(t, "github-access-token", tokens.AccessToken)
	require.NotNil(t, tokens.IDTokenClaims)
}

func TestRevokeRefreshToken(t *testing.T) {
	t.Parallel()

	var provider github.Provider

	require.NoError(t, provider.RevokeRefreshToken(t.Context(), slog.New(slog.DiscardHandler), nil, "github-access-token"))
}
