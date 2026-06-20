package oauth2

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"golang.org/x/oauth2"
)

// checkClientIPAddr verifies that the HTTP client address matches the VPN client address from the OAuth2 state.
func checkClientIPAddr(r *http.Request, conf config.Config, session state.State) error {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return fmt.Errorf("unable to split remote address %s: %w", r.RemoteAddr, err)
	}

	if conf.HTTP.EnableProxyHeaders {
		if fwdAddress := r.Header.Get("X-Forwarded-For"); fwdAddress != "" {
			clientIP = strings.TrimSpace(strings.Split(fwdAddress, ",")[0])
		}
	}

	if clientIP != session.IPAddr {
		return fmt.Errorf("%w: http client ip %s and vpn ip %s is different", ErrClientRejected, clientIP, session.IPAddr)
	}

	return nil
}

// getAuthorizeParams parses the authorizeParams string and returns a slice of rp.URLParamOpt.
func getAuthorizeParams(authorizeParams string) ([]rp.URLParamOpt, error) {
	authorizeParamsQuery, err := url.ParseQuery(authorizeParams)
	if err != nil {
		return nil, fmt.Errorf("unable to parse '%s': %w", authorizeParams, err)
	}

	params := make([]rp.URLParamOpt, 0, len(authorizeParamsQuery))

	for key, value := range authorizeParamsQuery {
		if len(value) == 0 {
			return nil, fmt.Errorf("authorize param %s does not have values", key)
		}

		params = append(params, rp.WithURLParam(key, value[0]))
	}

	return params, nil
}

// getNonce returns OAuth2 nonce for the given client ID.
func (c *Client) getNonce(id string) string {
	nonce := sha256.New()
	nonce.Write([]byte(id))
	nonce.Write([]byte(c.conf.HTTP.Secret.String()))

	return hex.EncodeToString(nonce.Sum(nil))
}

// OAuthConfig returns the underlying [oauth2.Config] used by the relying party.
// It is primarily exposed for tests that need direct access to the client
// configuration.
func (c *Client) OAuthConfig() *oauth2.Config {
	return c.relyingParty.OAuthConfig()
}

// EncryptState encrypts an OAuth2 state payload for use in authorization redirects.
func (c *Client) EncryptState(oidcState state.State) (state.EncryptedState, error) {
	encryptedState, err := state.Encrypt(c.stateCrypto, oidcState)
	if err != nil {
		return "", fmt.Errorf("encrypt state: %w", err)
	}

	return encryptedState, nil
}
