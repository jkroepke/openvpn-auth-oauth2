package azuread

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/caarlos0/env/v8"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
)

type providerConfig struct {
	authority string   `env:"OAUTH2_AZURE_AD_AUTHORITY" envDefault:"https://login.microsoftonline.com/${OAUTH_AZURE_AD_TENANT_ID}" envExpand:"true"`
	tenantId  string   `env:"OAUTH2_AZURE_AD_TENANT_ID"`
	clientId  string   `env:"OAUTH2_AZURE_AD_CLIENT_ID"`
	scopes    []string `env:"OAUTH2_AZURE_AD_TOKEN_SCOPES" envSeparator:" "`

	matchUsernameClientCn   bool   `env:"OAUTH2_AZURE_AD_MATCH_USERNAME_CLIENT_CN" envDefault:"true"`
	matchUsernameTokenField string `env:"OAUTH2_AZURE_AD_MATCH_USERNAME_TOKEN_FIELD" envDefault:"PreferredUsername"`
	matchClientIp           bool   `env:"OAUTH2_AZURE_AD_MATCH_CLIENT_IP" envDefault:"false"`
}

type Provider struct {
	*providerConfig

	app     public.Client
	devCode public.DeviceCode
}

func New() (*Provider, error) {
	conf := &providerConfig{}

	if err := env.ParseWithOptions(&conf, env.Options{RequiredIfNoDef: true}); err != nil {
		return &Provider{}, err
	}

	app, err := public.New(conf.clientId, public.WithAuthority(conf.authority))

	if err != nil {
		return nil, fmt.Errorf("error while create new azure ad public client: %v", err)
	}

	return &Provider{
		app:            app,
		providerConfig: conf,
	}, nil
}

func (p *Provider) StartAuthentication(ctx context.Context) (string, error) {
	devCode, err := p.app.AcquireTokenByDeviceCode(ctx, p.scopes)

	if err != nil {
		return "", fmt.Errorf("error while acquireTokenByDeviceCode: %v", err)
	}

	p.devCode = devCode

	return devCode.Result.VerificationURL, nil
}

func (p *Provider) ValidateAuthentication(ctx context.Context) error {
	result, err := p.devCode.AuthenticationResult(ctx)
	if err != nil {
		return fmt.Errorf("error while getting AuthenticationResult: %v", err)
	}

	if p.matchUsernameClientCn {
		commonName, ok := os.LookupEnv(openvpn.EnvVarCommonName)
		if !ok {
			return fmt.Errorf("can't find %s environment variable", openvpn.EnvVarCommonName)
		}

		field := reflect.Indirect(reflect.ValueOf(result.IDToken)).FieldByName(p.matchUsernameTokenField)
		if commonName != field.String() {
			return fmt.Errorf(
				"client %s does not match AD token field '%s' are different. OpenVPN: %s, AzureAD: %s",
				openvpn.EnvVarCommonName,
				p.matchUsernameTokenField,
				commonName,
				field.String(),
			)
		}
	}

	if p.matchClientIp {
		clientIp, ok := os.LookupEnv(openvpn.EnvVarClientIp)
		if !ok {
			return fmt.Errorf("can't find %s environment variable", openvpn.EnvVarClientIp)
		}

		if clientIpToken, ok := result.IDToken.AdditionalFields["ip_addr"]; ok {
			if clientIpToken != clientIp {
				return fmt.Errorf("client ip from OpenVPN and AzureAD are different. OpenVPN: %s, AzureAD: %s", clientIp, clientIpToken)
			}
		} else {
			return errors.New("missing ip_addr field in Azure AD token")
		}
	}

	return nil
}
