package config

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
)

// Validate validates the config.
func Validate(mode int, conf Config) error {
	if err := validateOAuth2Config(conf); err != nil {
		return err
	}

	if err := validateOpenVPNConfig(conf); err != nil {
		return err
	}

	if err := validateHTTPConfig(conf); err != nil {
		return err
	}

	if mode == ManagementClient {
		for key, value := range map[string]types.URL{
			"openvpn.addr": conf.OpenVPN.Addr,
		} {
			if value.IsEmpty() {
				return fmt.Errorf("%s is %w", key, ErrRequired)
			}
		}

		if !slices.Contains([]string{"tcp", "unix"}, conf.OpenVPN.Addr.Scheme) {
			return errors.New("openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported")
		}
	}

	return nil
}

// validateHTTPConfig validates the HTTP configuration.
func validateHTTPConfig(conf Config) error {
	if conf.HTTP.Secret.String() == "" {
		return fmt.Errorf("http.secret is %w", ErrRequired)
	}

	if err := validateEncryptionSecret(conf.HTTP.Secret); err != nil {
		return fmt.Errorf("http.secret %w", err)
	}

	if conf.HTTP.BaseURL.IsEmpty() {
		return fmt.Errorf("http.baseurl is %w", ErrRequired)
	}

	if err := validateURL(conf.HTTP.BaseURL); err != nil {
		return fmt.Errorf("http.baseurl: %w", err)
	}

	if err := conf.HTTP.Template.Execute(io.Discard, map[string]string{
		"title":   "",
		"message": "",
		"errorID": "",
	}); err != nil {
		return fmt.Errorf("invalid rendering http.template: %w", err)
	}

	return nil
}

// validateOpenVPNConfig validates the OpenVPN configuration.
func validateOpenVPNConfig(conf Config) error {
	if conf.OAuth2.OpenVPNUsernameCEL != "" && conf.OAuth2.OpenVPNUsernameClaim != "" {
		return errors.New("only one of oauth2.openvpn-username-cel or oauth2.openvpn-username-claim is allowed")
	}

	return nil
}

// validateOAuth2Config validates the OAuth2 configuration.
func validateOAuth2Config(conf Config) error {
	if err := validateOAuth2Issuer(conf.OAuth2); err != nil {
		return err
	}

	if err := validateOAuth2Client(conf.OAuth2.Client); err != nil {
		return err
	}

	if err := validateOAuth2Endpoints(conf.OAuth2.Endpoints); err != nil {
		return err
	}

	if err := validateOAuth2Refresh(conf.OAuth2.Refresh); err != nil {
		return err
	}

	if err := validateOAuth2ClientConfig(conf); err != nil {
		return err
	}

	return validateOAuth2UserInfo(conf.OAuth2)
}

// validateOAuth2Issuer validates the OAuth2 issuer configuration.
func validateOAuth2Issuer(oauth2Conf OAuth2) error {
	if oauth2Conf.Issuer.IsEmpty() {
		return fmt.Errorf("oauth2.issuer is %w", ErrRequired)
	}

	if err := validateURL(oauth2Conf.Issuer); err != nil {
		return fmt.Errorf("oauth2.issuer: %w", err)
	}

	return nil
}

// validateOAuth2Client validates the OAuth2 client configuration.
func validateOAuth2Client(client OAuth2Client) error {
	if client.ID == "" {
		return fmt.Errorf("oauth2.client.id is %w", ErrRequired)
	}

	if client.Secret.String() == "" && client.PrivateKey.String() == "" {
		return fmt.Errorf("one of oauth2.client.private-key or oauth2.client.secret is %w", ErrRequired)
	}

	if client.Secret.String() != "" && client.PrivateKey.String() != "" {
		return errors.New("only one of oauth2.client.private-key or oauth2.client.secret is allowed")
	}

	return nil
}

// validateOAuth2Endpoints validates the OAuth2 endpoints configuration.
func validateOAuth2Endpoints(endpoints OAuth2Endpoints) error {
	if err := validateURL(endpoints.Discovery); err != nil {
		return fmt.Errorf("oauth2.endpoint.discovery: %w", err)
	}

	if err := validateURL(endpoints.Token); err != nil {
		return fmt.Errorf("oauth2.endpoint.token: %w", err)
	}

	if err := validateURL(endpoints.Auth); err != nil {
		return fmt.Errorf("oauth2.endpoint.auth: %w", err)
	}

	return nil
}

// validateOAuth2Refresh validates the OAuth2 refresh token configuration.
func validateOAuth2Refresh(refresh OAuth2Refresh) error {
	if refresh.Enabled {
		if err := validateEncryptionSecret(refresh.Secret); err != nil {
			return fmt.Errorf("oauth2.refresh.secret %w", err)
		}
	}

	return nil
}

// validateOAuth2ClientConfig validates the client config directory settings.
func validateOAuth2ClientConfig(conf Config) error {
	if !conf.OpenVPN.ClientConfig.Enabled {
		return nil
	}

	if conf.OpenVPN.CommonName.Mode == CommonNameModeOmit {
		return errors.New("openvpn.common-name.mode: omit is not supported with openvpn.client-config.enabled")
	}

	file, err := conf.OpenVPN.ClientConfig.Path.Open(".")
	if err != nil {
		return fmt.Errorf("openvpn.client-config.path: %w", err)
	}

	_ = file.Close()

	return nil
}

// validateOAuth2UserInfo validates the user info configuration.
func validateOAuth2UserInfo(oauth2Conf OAuth2) error {
	if !oauth2Conf.Endpoints.Auth.IsEmpty() && !oauth2Conf.Endpoints.Token.IsEmpty() {
		if oauth2Conf.UserInfo {
			return errors.New("oauth2.userinfo: cannot be used if oauth2.endpoint.auth and oauth2.endpoint.token is set")
		}
	}

	return nil
}

func validateURL(uri types.URL) error {
	if uri.IsEmpty() {
		return nil
	}

	if !slices.Contains([]string{"http", "https"}, uri.Scheme) {
		return errors.New("invalid URL. only http:// or https:// scheme supported")
	}

	return nil
}

func validateEncryptionSecret(secret types.Secret) error {
	if !slices.Contains([]int{16, 24, 32}, len(secret.String())) {
		return errors.New("requires a length of 16, 24 or 32")
	}

	return nil
}
