package config

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
)

// Validate validates the config.
func Validate(mode int, conf Config) error { //nolint:cyclop
	for key, value := range map[string]string{
		"oauth2.client.id": conf.OAuth2.Client.ID,
	} {
		if value == "" {
			return fmt.Errorf("%s is %w", key, ErrRequired)
		}
	}

	for key, value := range map[string]Secret{
		"http.secret":          conf.HTTP.Secret,
		"oauth2.client.secret": conf.OAuth2.Client.Secret,
	} {
		if value.String() == "" {
			return fmt.Errorf("%s is %w", key, ErrRequired)
		}
	}

	for key, value := range map[string]*url.URL{
		"http.baseurl":  conf.HTTP.BaseURL,
		"oauth2.issuer": conf.OAuth2.Issuer,
	} {
		if IsURLEmpty(value) {
			return fmt.Errorf("%s is %w", key, ErrRequired)
		}
	}

	if !slices.Contains([]int{16, 24, 32}, len(conf.HTTP.Secret)) {
		return errors.New("http.secret requires a length of 16, 24 or 32")
	}

	for key, uri := range map[string]*url.URL{
		"http.baseurl":              conf.HTTP.BaseURL,
		"oauth2.issuer":             conf.OAuth2.Issuer,
		"oauth2.endpoint.discovery": conf.OAuth2.Endpoints.Discovery,
		"oauth2.endpoint.token":     conf.OAuth2.Endpoints.Token,
		"oauth2.endpoint.auth":      conf.OAuth2.Endpoints.Auth,
	} {
		if IsURLEmpty(uri) {
			continue
		}

		if !slices.Contains([]string{"http", "https"}, uri.Scheme) {
			return fmt.Errorf("%s: invalid URL. only http:// or https:// scheme supported", key)
		}
	}

	if conf.OAuth2.Refresh.Enabled {
		if !slices.Contains([]int{16, 24, 32}, len(conf.OAuth2.Refresh.Secret)) {
			return errors.New("oauth2.refresh.secret requires a length of 16, 24 or 32")
		}
	}

	if mode == ManagementClient {
		for key, value := range map[string]*url.URL{
			"openvpn.addr": conf.OpenVpn.Addr,
		} {
			if IsURLEmpty(value) {
				return fmt.Errorf("%s is %w", key, ErrRequired)
			}
		}

		if !slices.Contains([]string{"tcp", "unix"}, conf.OpenVpn.Addr.Scheme) {
			return errors.New("openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported")
		}
	}

	return nil
}
