package config

import (
	"log/slog"
	"net/url"
	"text/template"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/ui"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/ui/assets"
	"golang.org/x/oauth2"
)

const (
	CommonName = "common_name"
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
		AssetPath: types.FS{FS: assets.FS},
		BaseURL: types.URL{URL: &url.URL{
			Scheme: "http",
			Host:   "localhost:9000",
		}},
		Listen: ":9000",
		TLS:    false,
		Check: HTTPCheck{
			IPAddr: false,
		},
		Template: types.Template{Template: template.Must(template.New("index.gohtml").ParseFS(ui.Template, "index.gohtml"))},
	},
	OpenVpn: OpenVpn{
		Addr: types.URL{URL: &url.URL{
			Scheme:   "unix",
			Path:     "/run/openvpn/server.sock",
			OmitHost: true,
		}},
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
			Address: types.URL{URL: &url.URL{
				Scheme:   "unix",
				Path:     "/run/openvpn-auth-oauth2/server.sock",
				OmitHost: true,
			}},
			SocketMode:  660,
			SocketGroup: "",
		},
		CommandTimeout: 10 * time.Second,
	},
	OAuth2: OAuth2{
		AuthStyle: OAuth2AuthStyle(oauth2.AuthStyleInParams),
		Client:    OAuth2Client{},
		Endpoints: OAuth2Endpoints{
			Auth:      types.URL{URL: &url.URL{Scheme: "", Host: ""}},
			Discovery: types.URL{URL: &url.URL{Scheme: "", Host: ""}},
			Token:     types.URL{URL: &url.URL{Scheme: "", Host: ""}},
		},
		Issuer:   types.URL{URL: &url.URL{Scheme: "", Host: ""}},
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
