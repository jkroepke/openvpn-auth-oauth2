package oauth2

import (
	"fmt"
	"net/url"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
)

func Configure(conf *config.Config) (rp.RelyingParty, error) {
	uri, err := url.Parse(conf.Http.BaseUrl)
	if err != nil {
		return nil, fmt.Errorf("http.baseurl: %v", err)
	}

	redirectURI := fmt.Sprintf("%s/oauth2/callback", conf.Http.BaseUrl)

	cookieKey := []byte(conf.Http.SessionSecret)
	cookieHandler := httphelper.NewCookieHandler(cookieKey, cookieKey,
		httphelper.WithUnsecure(),
		httphelper.WithMaxAge(1800),
		httphelper.WithPath("/oauth2"),
		httphelper.WithDomain(uri.Hostname()),
	)

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
	}

	if conf.Oauth2.Pkce {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	return rp.NewRelyingPartyOIDC(
		conf.Oauth2.Issuer,
		conf.Oauth2.Client.Id,
		conf.Oauth2.Client.Secret,
		redirectURI,
		conf.Oauth2.Scopes,
		options...,
	)
}
