package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
)

// Validate validates the config.
func Validate(mode int, conf Config) error {
	if err := validateHTTPConfig(conf); err != nil {
		return err
	}

	if err := validateOAuth2Config(conf); err != nil {
		return err
	}

	if mode == ManagementClient {
		for key, value := range map[string]*URL{
			"openvpn.addr": conf.OpenVpn.Addr,
		} {
			if value.IsEmpty() {
				return fmt.Errorf("%s is %w", key, ErrRequired)
			}
		}

		if !slices.Contains([]string{"tcp", "unix"}, conf.OpenVpn.Addr.Scheme) {
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

	if conf.HTTP.AssetPath != "" {
		if _, err := os.ReadDir(conf.HTTP.AssetPath); err != nil {
			return fmt.Errorf("http.assets-path: %w", err)
		}
	}

	if err := conf.HTTP.CallbackTemplate.Execute(io.Discard, map[string]string{
		"title":   "",
		"message": "",
		"errorID": "",
	}); err != nil {
		return fmt.Errorf("invalid rendering http.template: %w", err)
	}

	return nil
}

func validateOAuth2Config(conf Config) error {
	if conf.OAuth2.Issuer.IsEmpty() {
		return fmt.Errorf("oauth2.issuer is %w", ErrRequired)
	}

	if conf.OAuth2.Client.ID == "" {
		return fmt.Errorf("oauth2.client.id is %w", ErrRequired)
	}

	if conf.OAuth2.Client.Secret.String() == "" && conf.OAuth2.Client.PrivateKey == "" {
		return fmt.Errorf("one of oauth2.client.private-key or oauth2.client.secret is %w", ErrRequired)
	} else if conf.OAuth2.Client.Secret.String() != "" && conf.OAuth2.Client.PrivateKey != "" {
		return errors.New("only one of oauth2.client.private-key or oauth2.client.secret is allowed")
	}

	for key, uri := range map[string]*URL{
		"oauth2.issuer":             conf.OAuth2.Issuer,
		"oauth2.endpoint.discovery": conf.OAuth2.Endpoints.Discovery,
		"oauth2.endpoint.token":     conf.OAuth2.Endpoints.Token,
		"oauth2.endpoint.auth":      conf.OAuth2.Endpoints.Auth,
	} {
		if err := validateURL(uri); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}

	if conf.OAuth2.Refresh.Enabled {
		if err := validateEncryptionSecret(conf.OAuth2.Refresh.Secret); err != nil {
			return fmt.Errorf("oauth2.refresh.secret %w", err)
		}
	}

	return nil
}

func validateURL(uri *URL) error {
	if uri.IsEmpty() {
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
