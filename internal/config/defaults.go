package config

import (
	"log/slog"
	"text/template"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/ui"
	"golang.org/x/oauth2"
)

//nolint:gochecknoglobals
var Defaults = Config{
	Debug: Debug{
		Listen: ":9001",
	},
	Log: Log{
		Format:      "console",
		Level:       slog.LevelInfo,
		VPNClientIP: true,
	},
	HTTP: HTTP{
		BaseURL: &URL{
			Scheme: "http",
			Host:   "localhost:9000",
		},
		Listen: ":9000",
		TLS:    false,
		Check: HTTPCheck{
			IPAddr: false,
		},
		CallbackTemplate: template.Must(template.New("index.gohtml").ParseFS(ui.Template, "index.gohtml")),
	},
	OpenVpn: OpenVpn{
		Addr: &URL{
			Scheme:   "unix",
			Path:     "/run/openvpn/server.sock",
			OmitHost: true,
		},
		AuthTokenUser:      true,
		AuthPendingTimeout: 3 * time.Minute,
		CommonName: OpenVPNCommonName{
			EnvironmentVariableName: "common_name",
			Mode:                    CommonNameModePlain,
		},
		OverrideUsername: false,
		Bypass: OpenVpnBypass{
			CommonNames: make([]string, 0),
		},
		Passthrough: OpenVPNPassthrough{
			Enabled: false,
			Address: &URL{
				Scheme:   "unix",
				Path:     "/run/openvpn-auth-oauth2/server.sock",
				OmitHost: true,
			},
			SocketMode:  660,
			SocketGroup: "",
		},
	},
	OAuth2: OAuth2{
		AuthStyle: OAuth2AuthStyle(oauth2.AuthStyleInParams),
		Client:    OAuth2Client{},
		Endpoints: OAuth2Endpoints{
			Auth:      &URL{Scheme: "", Host: ""},
			Discovery: &URL{Scheme: "", Host: ""},
			Token:     &URL{Scheme: "", Host: ""},
		},
		Issuer:   &URL{Scheme: "", Host: ""},
		Nonce:    true,
		PKCE:     true,
		Provider: "generic",
		Refresh: OAuth2Refresh{
			Expires:      time.Hour * 8,
			ValidateUser: true,
		},
		Scopes: make([]string, 0),
		Validate: OAuth2Validate{
			Groups: make([]string, 0),
			IPAddr: false,
			Issuer: true,
			Roles:  make([]string, 0),
		},
	},
}
