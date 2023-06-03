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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/provider"
)

type providerConfig struct {
	authority string   `env:"OPENVPN_OAUTH2_AZURE_AD_AUTHORITY" envDefault:"https://login.microsoftonline.com/${OAUTH2_AZURE_AD_TENANT_ID}" envExpand:"true"`
	tenantId  string   `env:"OPENVPN_OAUTH2_AZURE_AD_TENANT_ID"` //nolint:unused
	clientId  string   `env:"OPENVPN_OAUTH2_AZURE_AD_CLIENT_ID"`
	scopes    []string `env:"OPENVPN_OAUTH2_AZURE_AD_TOKEN_SCOPES" envSeparator:" "`

	matchUsernameClientCn   bool   `env:"OPENVPN_OAUTH2_AZURE_AD_MATCH_USERNAME_CLIENT_CN" envDefault:"true"`
	matchUsernameTokenField string `env:"OPENVPN_OAUTH2_AZURE_AD_MATCH_USERNAME_TOKEN_FIELD" envDefault:"PreferredUsername"`
	matchClientIp           bool   `env:"OPENVPN_OAUTH2_AZURE_AD_MATCH_CLIENT_IP" envDefault:"false"`
}

type Provider struct {
	config *providerConfig

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
		app:    app,
		config: conf,
	}, nil
}

func (p *Provider) StartDeviceAuthorization(ctx context.Context) (*provider.DeviceCodeResponse, error) {
	devCode, err := p.app.AcquireTokenByDeviceCode(ctx, p.config.scopes)

	if err != nil {
		return &provider.DeviceCodeResponse{}, fmt.Errorf("error while acquireTokenByDeviceCode: %v", err)
	}

	p.devCode = devCode

	return &provider.DeviceCodeResponse{
		UserCode:        devCode.Result.UserCode,
		VerificationURI: devCode.Result.VerificationURL,
	}, nil
}

func (p *Provider) ValidateDeviceAuthorization(ctx context.Context) error {
	result, err := p.devCode.AuthenticationResult(ctx)
	if err != nil {
		return fmt.Errorf("error while getting AuthenticationResult: %v", err)
	}

	if p.config.matchUsernameClientCn {
		err := p.validateCommonName(result)
		if err != nil {
			return err
		}
	}

	if p.config.matchClientIp {
		err := p.validateClientIp(result)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) validateCommonName(result public.AuthResult) error {
	commonName, err := openvpn.GetClientCommonName()
	if err != nil {
		return err
	}

	username, ok := result.IDToken.AdditionalFields[p.config.matchUsernameTokenField]

	if !ok {
		fieldValue := reflect.Indirect(reflect.ValueOf(result.IDToken)).FieldByName(p.config.matchUsernameTokenField)
		if !fieldValue.IsValid() {
			return fmt.Errorf(
				"token field '%s' is invalid or undefined",
				p.config.matchUsernameTokenField,
			)
		}
		username = fieldValue.String()
	}

	if commonName != username {
		return fmt.Errorf(
			"client %s does not match AD token field '%s' are different. OpenVPN: %s, AzureAD: %s",
			openvpn.EnvVarCommonName,
			p.config.matchUsernameTokenField,
			commonName,
			username,
		)
	}
	return nil
}

func (p *Provider) validateClientIp(result public.AuthResult) error {
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
	return nil
}
