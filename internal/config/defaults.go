package config

import (
	"log/slog"
	"net/url"
	"os"
	"text/template"
	"time"

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
		AssetPath: assets.FS,
		BaseURL: &url.URL{
			Scheme: "http",
			Host:   "localhost:9000",
		},
		Listen: ":9000",
		TLS:    false,
		Check: HTTPCheck{
			IPAddr: false,
		},
		Template: template.Must(template.New("index.gohtml").ParseFS(ui.Template, "index.gohtml")),
	},
	OpenVPN: OpenVPN{
		Addr: &url.URL{
			Scheme:   "unix",
			Path:     "/run/openvpn/server.sock",
			OmitHost: true,
		},
		AuthTokenUser:      true,
		AuthPendingTimeout: 3 * time.Minute,
		ClientConfig: OpenVPNConfig{
			Path:         os.DirFS("/etc/openvpn-auth-oauth2/client-config-dir/"),
			UserSelector: OpenVPNConfigProfileSelector{},
		},
		CommonName: OpenVPNCommonName{
			EnvironmentVariableName: "common_name",
			Mode:                    CommonNameModePlain,
		},
		Bypass: OpenVPNBypass{},
		Passthrough: OpenVPNPassthrough{
			Address: &url.URL{
				Scheme:   "unix",
				Path:     "/run/openvpn-auth-oauth2/server.sock",
				OmitHost: true,
			},
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
			Auth:      nil,
			Discovery: nil,
			Token:     nil,
		},
		Issuer:               nil,
		Nonce:                true,
		RefreshNonce:         OAuth2RefreshNonceAuto,
		PKCE:                 true,
		UserInfo:             false,
		GroupsClaim:          "groups",
		Provider:             "generic",
		OpenVPNUsernameClaim: "preferred_username",
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
