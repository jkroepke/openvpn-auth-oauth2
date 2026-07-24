package generic

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

func TestRevokeRelyingPartyHTTPClientReturnsCopy(t *testing.T) {
	t.Parallel()

	redirectErr := errors.New("original redirect")
	originalClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return redirectErr
		},
		Timeout: time.Second,
	}

	wrapped := revokeHTTPClientRelyingParty{RelyingParty: testRevokeRelyingParty{httpClient: originalClient}}
	revokeClient := wrapped.HttpClient()

	require.NotSame(t, originalClient, revokeClient)
	require.Equal(t, originalClient.Timeout, revokeClient.Timeout)

	revokeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	require.ErrorIs(t, originalClient.CheckRedirect(nil, nil), redirectErr)
	require.ErrorIs(t, revokeClient.CheckRedirect(nil, nil), http.ErrUseLastResponse)
}

type testRevokeRelyingParty struct {
	rp.RelyingParty

	httpClient *http.Client
}

//nolint:revive // HttpClient is required by the upstream rp.RelyingParty interface.
func (r testRevokeRelyingParty) HttpClient() *http.Client {
	return r.httpClient
}
