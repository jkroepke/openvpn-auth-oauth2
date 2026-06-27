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
	CommonName  = "common_name"
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
	SchemeTCP   = "tcp"
	SchemeUNIX  = "unix"
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
			Scheme: SchemeHTTP,
			Host:   "localhost:9000",
		}},
		Listen: ":9000",
		TLS:    false,
		Check: HTTPCheck{
			IPAddr: false,
		},
		Template: types.Template{Template: template.Must(template.New("index.gohtml").ParseFS(ui.Template, "index.gohtml"))},
	},
	OpenVPN: OpenVPN{
		Addr: types.URL{URL: &url.URL{
			Scheme:   SchemeUNIX,
			Path:     "/run/openvpn/server.sock",
			OmitHost: true,
		}},
		AuthTokenUser:      true,
		AuthPendingTimeout: 3 * time.Minute,
		ClientConfig: OpenVPNConfig{
			Enabled: false,
			Path:    types.NewRootFS("/etc/openvpn-auth-oauth2/client-config-dir/"),
			UserSelector: OpenVPNConfigProfileSelector{
				Enabled:      false,
				StaticValues: make(types.StringSlice, 0),
			},
		},
		CommonName: OpenVPNCommonName{
			EnvironmentVariableName: "common_name",
			Mode:                    CommonNameModePlain,
		},
		OverrideUsername: false,
		Bypass: OpenVPNBypass{
			CommonNames: types.RegexpSlice{},
		},
		Passthrough: OpenVPNPassthrough{
			Enabled: false,
			Address: types.URL{URL: &url.URL{
				Scheme:   SchemeUNIX,
				Path:     "/run/openvpn-auth-oauth2/server.sock",
				OmitHost: true,
			}},
			SocketMode:  660,
			SocketGroup: "",
		},
		CommandTimeout:   10 * time.Second,
		ReAuthentication: true,
	},
	OAuth2: OAuth2{
		AuthStyle: OAuth2AuthStyle(oauth2.AuthStyleInParams),
		Client:    OAuth2Client{},
		Endpoints: OAuth2Endpoints{
			Auth:      types.URL{URL: &url.URL{Scheme: "", Host: ""}},
			Discovery: types.URL{URL: &url.URL{Scheme: "", Host: ""}},
			Token:     types.URL{URL: &url.URL{Scheme: "", Host: ""}},
		},
		Issuer:          types.URL{URL: &url.URL{Scheme: "", Host: ""}},
		Nonce:           true,
		RefreshNonce:    OAuth2RefreshNonceAuto,
		PKCE:            true,
		UserInfo:        false,
		GroupsClaim:     "groups",
		Provider:        "generic",
		OpenVPNUsername: "oauth2TokenClaims.preferred_username",
		Refresh: OAuth2Refresh{
			Expires:      time.Hour * 8,
			ValidateUser: true,
		},
		Scopes: make([]string, 0),
		Validate: OAuth2Validate{
			Groups: make([]string, 0),
			Issuer: true,
		},
	},
	Provider: Provider{
		Google: ProviderGoogle{
			Validate: ProviderGoogleValidate{
				GroupsTransitive: false,
			},
		},
	},
}
