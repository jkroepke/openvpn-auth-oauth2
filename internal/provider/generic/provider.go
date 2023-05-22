package generic

import (
	"context"
	"fmt"
	"time"

	"github.com/caarlos0/env/v8"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/provider"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/exp/maps"
)

type providerConfig struct {
	issuer                  string   `env:"OAUTH2_GENERIC_ISSUER"`
	clientId                string   `env:"OAUTH2_GENERIC_CLIENT_ID"`
	clientSecret            string   `env:"OAUTH2_GENERIC_CLIENT_SECRET" envDefault:""`
	scopes                  []string `env:"OAUTH2_GENERIC_TOKEN_SCOPES" envSeparator:" "`
	matchUsernameClientCn   bool     `env:"OAUTH2_GENERIC_MATCH_USERNAME_CLIENT_CN" envDefault:"true"`
	matchUsernameTokenField string   `env:"OAUTH2_GENERIC_MATCH_USERNAME_TOKEN_FIELD" envDefault:"sub"`
}

type Provider struct {
	config  *providerConfig
	client  rp.RelyingParty
	devCode *oidc.DeviceAuthorizationResponse
}

func New() (*Provider, error) {
	conf := &providerConfig{}

	if err := env.ParseWithOptions(&conf, env.Options{RequiredIfNoDef: true}); err != nil {
		return &Provider{}, err
	}

	client, err := rp.NewRelyingPartyOIDC(conf.issuer, conf.clientId, conf.clientSecret, "", conf.scopes)
	if err != nil {
		return &Provider{}, err
	}

	return &Provider{
		client: client,
	}, nil
}

func (p *Provider) StartDeviceAuthorization(_ context.Context) (*provider.DeviceCodeResponse, error) {
	devCode, err := rp.DeviceAuthorization(p.config.scopes, p.client)
	if err != nil {
		return &provider.DeviceCodeResponse{}, err
	}

	p.devCode = devCode

	return &provider.DeviceCodeResponse{
		UserCode:                devCode.UserCode,
		VerificationURI:         devCode.VerificationURI,
		VerificationURIComplete: devCode.VerificationURIComplete,
	}, nil
}

func (p *Provider) ValidateDeviceAuthorization(ctx context.Context) error {
	result, err := rp.DeviceAccessToken(ctx, p.devCode.DeviceCode, time.Duration(p.devCode.Interval)*time.Second, p.client)
	if err != nil {
		return fmt.Errorf("error while getting Poll: %v", err)
	}

	claims, err := rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, result.IDToken, p.client.IDTokenVerifier())
	if err != nil {
		return err
	}

	if p.config.matchUsernameClientCn {
		err := p.validateCommonName(claims)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) validateCommonName(claims *oidc.IDTokenClaims) error {
	commonName, err := openvpn.GetClientCommonName()
	if err != nil {
		return err
	}

	if username, ok := claims.Claims[p.config.matchUsernameTokenField]; ok {
		if commonName != username {
			return fmt.Errorf(
				"client %s does not match OIDC token claim '%s'. OpenVPN CN: %s, Claim: %s",
				openvpn.EnvVarCommonName,
				p.config.matchUsernameTokenField,
				commonName,
				username,
			)
		}
	} else {
		return fmt.Errorf(
			"claim '%s' does not exists in token. Availible claims: %v",
			p.config.matchUsernameTokenField,
			maps.Keys(claims.Claims),
		)
	}
	return nil
}
