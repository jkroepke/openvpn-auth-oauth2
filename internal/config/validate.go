package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
)

// Validate validates the config.
func Validate(conf Config) error {
	if err := validateOAuth2Config(conf); err != nil {
		return err
	}

	if err := validateOpenVPNConfig(conf); err != nil {
		return err
	}

	if err := validateHTTPConfig(conf); err != nil {
		return err
	}

	for key, value := range map[string]*url.URL{
		"openvpn.addr": conf.OpenVPN.Addr,
	} {
		if value == nil || (value.Scheme == "" && value.Host == "") {
			return fmt.Errorf("%s is %w", key, ErrRequired)
		}
	}

	if !slices.Contains([]string{"tcp", "unix"}, conf.OpenVPN.Addr.Scheme) {
		return errors.New("openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported")
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

	if conf.HTTP.BaseURL == nil || (conf.HTTP.BaseURL.Scheme == "" && conf.HTTP.BaseURL.Host == "") {
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
//
//nolint:cyclop
func validateOAuth2Config(conf Config) error {
	if conf.OAuth2.Issuer == nil || (conf.OAuth2.Issuer.Scheme == "" && conf.OAuth2.Issuer.Host == "") {
		return fmt.Errorf("oauth2.issuer is %w", ErrRequired)
	}

	if err := validateURL(conf.OAuth2.Issuer); err != nil {
		return fmt.Errorf("oauth2.issuer: %w", err)
	}

	if conf.OAuth2.Client.Secret.String() == "" && conf.OAuth2.Client.PrivateKey.String() == "" {
		return fmt.Errorf("one of oauth2.client.private-key or oauth2.client.secret is %w", ErrRequired)
	}

	if conf.OAuth2.Client.Secret.String() != "" && conf.OAuth2.Client.PrivateKey.String() != "" {
		return errors.New("only one of oauth2.client.private-key or oauth2.client.secret is allowed")
	}

	if err := validateURL(conf.OAuth2.Endpoints.Discovery); err != nil {
		return fmt.Errorf("oauth2.endpoint.discovery: %w", err)
	}

	if err := validateURL(conf.OAuth2.Endpoints.Token); err != nil {
		return fmt.Errorf("oauth2.endpoint.token: %w", err)
	}

	if err := validateURL(conf.OAuth2.Endpoints.Auth); err != nil {
		return fmt.Errorf("oauth2.endpoint.auth: %w", err)
	}

	if conf.OAuth2.Refresh.Enabled {
		if err := validateEncryptionSecret(conf.OAuth2.Refresh.Secret); err != nil {
			return fmt.Errorf("oauth2.refresh.secret %w", err)
		}
	}

	if conf.OpenVPN.ClientConfig.Enabled {
		if conf.OpenVPN.CommonName.Mode == CommonNameModeOmit {
			return errors.New("openvpn.common-name.mode: omit is not supported with openvpn.client-config.enabled")
		}

		file, err := conf.OpenVPN.ClientConfig.Path.Open(".")
		if err != nil {
			return fmt.Errorf("openvpn.client-config.path: %w", err)
		}

		_ = file.Close()
	}

	if isURLNotEmpty(conf.OAuth2.Endpoints.Auth) && isURLNotEmpty(conf.OAuth2.Endpoints.Token) {
		if conf.OAuth2.UserInfo {
			return errors.New("oauth2.userinfo: cannot be used if oauth2.endpoint.auth and oauth2.endpoint.token is set")
		}
	}

	return nil
}

// isURLNotEmpty checks if a URL is not nil and has at least scheme or host set.
func isURLNotEmpty(uri *url.URL) bool {
	return uri != nil && (uri.Scheme != "" || uri.Host != "")
}

func validateURL(uri *url.URL) error {
	if !isURLNotEmpty(uri) {
		return nil
	}

	if !slices.Contains([]string{"http", "https"}, uri.Scheme) {
		return errors.New("invalid URL. only http:// or https:// scheme supported")
	}

	return nil
}

func validateEncryptionSecret(secret Secret) error {
	if !slices.Contains([]int{16, 24, 32}, len(secret.String())) {
		return errors.New("requires a length of 16, 24 or 32")
	}

	return nil
}
