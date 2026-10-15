package oauth2

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// clientAssertionLifetime is the lifetime of the private_key_jwt client
// assertion sent with a client credentials request.
const clientAssertionLifetime = time.Minute

// ClientCredentialsToken requests an access token for the OAuth2 client
// itself with the client credentials grant, authenticating like the code
// exchange does: with the client secret, or with a private_key_jwt assertion
// if oauth2.client.private-key is set.
func (c *Client) ClientCredentialsToken(ctx context.Context, scopes ...string) (*oauth2.Token, error) {
	oauthConfig := c.relyingParty.OAuthConfig()

	conf := clientcredentials.Config{
		ClientID:     oauthConfig.ClientID,
		ClientSecret: oauthConfig.ClientSecret,
		TokenURL:     oauthConfig.Endpoint.TokenURL,
		Scopes:       scopes,
		AuthStyle:    oauthConfig.Endpoint.AuthStyle,
	}

	if signer := c.relyingParty.Signer(); signer != nil {
		audience := c.relyingParty.Issuer()
		if audience == "" {
			audience = conf.TokenURL
		}

		assertion, err := client.SignedJWTProfileAssertion(conf.ClientID, []string{audience}, clientAssertionLifetime, signer)
		if err != nil {
			return nil, fmt.Errorf("sign client assertion: %w", err)
		}

		conf.EndpointParams = url.Values{
			"client_assertion":      {assertion},
			"client_assertion_type": {oidc.ClientAssertionTypeJWTAssertion},
		}
	}

	token, err := conf.Token(context.WithValue(ctx, oauth2.HTTPClient, c.relyingParty.HttpClient()))
	if err != nil {
		return nil, fmt.Errorf("client credentials grant: %w", err)
	}

	return token, nil
}
