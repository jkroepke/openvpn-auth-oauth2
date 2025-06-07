package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"golang.org/x/oauth2"
)

const (
	Plugin = iota
	ManagementClient
)

type Config struct {
	ConfigFile string  `json:"config"  yaml:"config"`
	HTTP       HTTP    `json:"http"    yaml:"http"`
	Debug      Debug   `json:"debug"   yaml:"debug"`
	Log        Log     `json:"log"     yaml:"log"`
	OAuth2     OAuth2  `json:"oauth2"  yaml:"oauth2"`
	OpenVPN    OpenVPN `json:"openvpn" yaml:"openvpn"`
}

type HTTP struct {
	BaseURL            types.URL      `json:"baseurl"              yaml:"baseurl"`
	AssetPath          types.FS       `json:"assets-path"          yaml:"assets-path"`
	Template           types.Template `json:"template"             yaml:"template"`
	Listen             string         `json:"listen"               yaml:"listen"`
	CertFile           string         `json:"cert"                 yaml:"cert"`
	KeyFile            string         `json:"key"                  yaml:"key"`
	Secret             types.Secret   `json:"secret"               yaml:"secret"`
	TLS                bool           `json:"tls"                  yaml:"tls"`
	Check              HTTPCheck      `json:"check"                yaml:"check"`
	EnableProxyHeaders bool           `json:"enable-proxy-headers" yaml:"enable-proxy-headers"`
}

type HTTPCheck struct {
	IPAddr bool `json:"ipaddr" yaml:"ipaddr"`
}

type Log struct {
	Format      string     `json:"format"        yaml:"format"`
	Level       slog.Level `json:"level"         yaml:"level"`
	VPNClientIP bool       `json:"vpn-client-ip" yaml:"vpn-client-ip"`
}

type OpenVPN struct {
	Addr               types.URL          `json:"addr"                 yaml:"addr"`
	Password           types.Secret       `json:"password"             yaml:"password"`
	ClientConfig       OpenVPNConfig      `json:"client-config"        yaml:"client-config"`
	Bypass             OpenVPNBypass      `json:"bypass"               yaml:"bypass"`
	CommonName         OpenVPNCommonName  `json:"common-name"          yaml:"common-name"`
	Passthrough        OpenVPNPassthrough `json:"pass-through"         yaml:"pass-through"`
	AuthPendingTimeout time.Duration      `json:"auth-pending-timeout" yaml:"auth-pending-timeout"`
	CommandTimeout     time.Duration      `json:"command-timeout"      yaml:"command-timeout"`
	AuthTokenUser      bool               `json:"auth-token-user"      yaml:"auth-token-user"`
	OverrideUsername   bool               `json:"override-username"    yaml:"override-username"`
	ReAuthentication   bool               `json:"reauthentication"     yaml:"reauthentication"`
}

type OpenVPNBypass struct {
	CommonNames types.StringSlice `json:"common-names" yaml:"common-names"`
}
type OpenVPNConfig struct {
	Path       types.FS `json:"path"        yaml:"path"`
	TokenClaim string   `json:"token-claim" yaml:"token-claim"`
	Enabled    bool     `json:"enabled"     yaml:"enabled"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `json:"environment-variable-name" yaml:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `json:"mode"                      yaml:"mode"`
}

type OAuth2 struct {
	Endpoints       OAuth2Endpoints   `json:"endpoint"         yaml:"endpoint"`
	Issuer          types.URL         `json:"issuer"           yaml:"issuer"`
	Client          OAuth2Client      `json:"client"           yaml:"client"`
	AuthorizeParams string            `json:"authorize-params" yaml:"authorize-params"`
	Provider        string            `json:"provider"         yaml:"provider"`
	Scopes          types.StringSlice `json:"scopes"           yaml:"scopes"`
	Validate        OAuth2Validate    `json:"validate"         yaml:"validate"`
	Refresh         OAuth2Refresh     `json:"refresh"          yaml:"refresh"`
	AuthStyle       OAuth2AuthStyle   `json:"auth-style"       yaml:"auth-style"`
	Nonce           bool              `json:"nonce"            yaml:"nonce"`
	PKCE            bool              `json:"pkce"             yaml:"pkce"`
}

type OAuth2Client struct {
	ID           string       `json:"id"             yaml:"id"`
	Secret       types.Secret `json:"secret"         yaml:"secret"`
	PrivateKey   types.Secret `json:"private-key"    yaml:"private-key"`
	PrivateKeyID string       `json:"private-key-id" yaml:"private-key-id"`
}

type OAuth2Endpoints struct {
	Discovery types.URL `json:"discovery" yaml:"discovery"`
	Auth      types.URL `json:"auth"      yaml:"auth"`
	Token     types.URL `json:"token"     yaml:"token"`
}

type OAuth2Validate struct {
	CommonName              string            `json:"common-name"                yaml:"common-name"`
	Acr                     types.StringSlice `json:"acr"                        yaml:"acr"`
	Groups                  types.StringSlice `json:"groups"                     yaml:"groups"`
	Roles                   types.StringSlice `json:"roles"                      yaml:"roles"`
	IPAddr                  bool              `json:"ipaddr"                     yaml:"ipaddr"`
	Issuer                  bool              `json:"issuer"                     yaml:"issuer"`
	CommonNameCaseSensitive bool              `json:"common-name-case-sensitive" yaml:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Secret       types.Secret  `json:"secret"         yaml:"secret"`
	Expires      time.Duration `json:"expires"        yaml:"expires"`
	Enabled      bool          `json:"enabled"        yaml:"enabled"`
	UseSessionID bool          `json:"use-session-id" yaml:"use-session-id"`
	ValidateUser bool          `json:"validate-user"  yaml:"validate-user"`
}

type OpenVPNPassthrough struct {
	Address     types.URL    `json:"address"      yaml:"address"`
	Password    types.Secret `json:"password"     yaml:"password"`
	SocketGroup string       `json:"socket-group" yaml:"socket-group"`
	SocketMode  uint         `json:"socket-mode"  yaml:"socket-mode"`
	Enabled     bool         `json:"enabled"      yaml:"enabled"`
}

type Debug struct {
	Listen string `json:"listen" yaml:"listen"`
	Pprof  bool   `json:"pprof"  yaml:"pprof"`
}

type OpenVPNCommonNameMode int

const (
	CommonNameModePlain OpenVPNCommonNameMode = iota
	CommonNameModeOmit
	CommonNameModeOmitValue = "-"
)

//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) MarshalText() ([]byte, error) {
	switch s {
	case CommonNameModePlain:
		return []byte("plain"), nil
	case CommonNameModeOmit:
		return []byte("omit"), nil
	default:
		return nil, fmt.Errorf("unknown identitfer %d", s)
	}
}

//goland:noinspection GoMixedReceiverTypes
func (s *OpenVPNCommonNameMode) UnmarshalText(text []byte) error {
	config := strings.ToLower(string(text))
	switch config {
	case "plain":
		*s = CommonNameModePlain
	case "omit":
		*s = CommonNameModeOmit
	default:
		return fmt.Errorf("invalid value %s", config)
	}

	return nil
}

type OAuth2AuthStyle oauth2.AuthStyle

//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) AuthStyle() oauth2.AuthStyle {
	return oauth2.AuthStyle(s)
}

//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) MarshalText() ([]byte, error) {
	switch s {
	case OAuth2AuthStyle(oauth2.AuthStyleAutoDetect):
		return []byte("AuthStyleAutoDetect"), nil
	case OAuth2AuthStyle(oauth2.AuthStyleInParams):
		return []byte("AuthStyleInParams"), nil
	case OAuth2AuthStyle(oauth2.AuthStyleInHeader):
		return []byte("AuthStyleInHeader"), nil
	default:
		return nil, fmt.Errorf("unknown auth-style %d", s)
	}
}

//goland:noinspection GoMixedReceiverTypes
func (s *OAuth2AuthStyle) UnmarshalText(text []byte) error {
	config := strings.ToLower(string(text))
	switch config {
	case strings.ToLower("AuthStyleAutoDetect"):
		*s = OAuth2AuthStyle(oauth2.AuthStyleAutoDetect)
	case strings.ToLower("AuthStyleInParams"):
		*s = OAuth2AuthStyle(oauth2.AuthStyleInParams)
	case strings.ToLower("AuthStyleInHeader"):
		*s = OAuth2AuthStyle(oauth2.AuthStyleInHeader)
	default:
		return fmt.Errorf("unknown auth-style %d", s)
	}

	return nil
}

//goland:noinspection GoMixedReceiverTypes
func (c Config) String() string {
	jsonString, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}

	return string(jsonString)
}

func (h HTTP) MarshalJSON() ([]byte, error) {
	type Alias HTTP

	//nolint:wrapcheck
	return json.Marshal(&struct {
		Alias
	}{
		Alias: (Alias)(h),
	})
}

// ConfigHolder provides a thread-safe mechanism to store and access
// a shared *Config instance. It allows atomic replacement of the entire
// configuration object, which is ideal for long-running daemons that
// support dynamic configuration reloads.
//
// The configuration stored in ConfigHolder must be treated as immutable
// once set, to avoid data races.
type ConfigHolder struct {
	configFilePath string
	ptr            atomic.Pointer[Config]
}

func NewConfigHolder(configFilePath string, cfg *Config) *ConfigHolder {
	holder := &ConfigHolder{configFilePath: configFilePath}
	holder.set(cfg)

	return holder
}

// Get returns the current configuration.
//
// The returned *Config is safe for concurrent reads. Callers must not
// modify the returned config to preserve thread safety.
//
// If no configuration has been set yet, Get will return nil.
func (c *ConfigHolder) Get() *Config {
	return c.ptr.Load()
}

// Set atomically replaces the current configuration with the provided one.
//
// The new *Config must be fully initialized and must not be modified
// after being passed to Set. This ensures that all goroutines accessing
// the config via Get observe a consistent and immutable snapshot.
func (c *ConfigHolder) set(cfg *Config) {
	c.ptr.Store(cfg)
}

// Update atomically replaces the current configuration with a new one
// created by applying the provided function to the current config.
// If the current config is nil, it will use the provided default config
// to create the new configuration.
func (c *ConfigHolder) Reload() error {
	if c.configFilePath == "" {
		return nil
	}

	var config Config

	if err := config.ReadFromConfigFile(c.configFilePath); err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	cfg := c.Get()
	if cfg == nil {
		return fmt.Errorf("no configuration loaded, cannot reload from %s", c.configFilePath)
	}

	// Clone the old config
	cloned := *cfg

	// Replace only the updated part
	cloned.OpenVPN.Bypass.CommonNames = config.OpenVPN.Bypass.CommonNames

	c.set(&cloned)

	return nil
}
