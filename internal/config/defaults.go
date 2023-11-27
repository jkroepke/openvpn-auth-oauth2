package config

import (
	"net/url"
	"time"
)

//nolint:gochecknoglobals
var Defaults = Config{
	Log: Log{
		Format: "console",
		Level:  "info",
	},
	HTTP: HTTP{
		BaseURL: &url.URL{
			Scheme: "http",
			Host:   "localhost:9000",
		},
		Listen: ":9000",
		TLS:    false,
		Check: HTTPCheck{
			IPAddr: false,
		},
	},
	OpenVpn: OpenVpn{
		Addr: &url.URL{
			Scheme:   "unix",
			Path:     "/run/openvpn/server.sock",
			OmitHost: true,
		},
		AuthTokenUser:      true,
		AuthPendingTimeout: 3 * time.Minute,
		CommonName: OpenVPNCommonName{
			Mode: CommonNameModePlain,
		},
		Bypass: OpenVpnBypass{
			CommonNames: make([]string, 0),
		},
	},
	OAuth2: OAuth2{
		Provider: "generic",
		Issuer:   &url.URL{Scheme: "", Host: ""},
		Endpoints: OAuth2Endpoints{
			Auth:      &url.URL{Scheme: "", Host: ""},
			Discovery: &url.URL{Scheme: "", Host: ""},
			Token:     &url.URL{Scheme: "", Host: ""},
		},
		Client: OAuth2Client{},
		Validate: OAuth2Validate{
			Groups: make([]string, 0),
			Roles:  make([]string, 0),
			IPAddr: false,
			Issuer: true,
		},
		Scopes: []string{},
	},
}
