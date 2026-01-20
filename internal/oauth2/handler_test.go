package oauth2_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/crypto"
)

const invalid = "invalid"

func TestHandler(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		conf          config.Config
		state         state.State
		invalidState  bool
		xForwardedFor string
		preAllow      bool
		postAllow     bool
	}{
		{
			"default",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with username defined",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, UsernameIsDefined: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with acr values",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Acr = []string{"phr"}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.Nonce = true
				conf.OAuth2.PKCE = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			false,
		},
		{
			"with template",
			func() config.Config {
				tmpl, err := types.NewTemplate("../../LICENSE.txt")
				require.NoError(t, err)

				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.HTTP.Template = tmpl
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with userinfo enabled",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = []string{"group1"}
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.UserInfo = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with userinfo enabled + validate groups",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = []string{"group0", "group1"}
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.UserInfo = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with userinfo enabled + missing validate groups",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = []string{"group0"}
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.UserInfo = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			false,
		},
		{
			"with ipaddr",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with short-url",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.ShortURL = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with ipaddr + forwarded-for",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2",
			true,
			true,
		},
		{
			"with ipaddr + disabled forwarded-for",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2",
			false,
			false,
		},
		{
			"with ipaddr + multiple forwarded-for",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config found",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"name.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config and custom claim",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.TokenClaim = "sub"
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"id1.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config not found",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "client"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"static"}
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"static.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values + claim string",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"static"}
				conf.OpenVPN.ClientConfig.TokenClaim = "sub"
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"id1.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values + claim array",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"aaa"}
				conf.OpenVPN.ClientConfig.TokenClaim = "amr"
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"pwd.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values + claim invalid",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"static"}
				conf.OpenVPN.ClientConfig.TokenClaim = invalid
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"static.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values + not found",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"not found"}
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"static.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "client"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + multiple static values",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"group1", "group2"}
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"group2.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with empty state",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.State{},
			false,
			"127.0.0.1",
			true,
			true,
		},
		{
			"with invalid state",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.State{},
			true,
			"127.0.0.1",
			true,
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			conf, openVPNClient, managementInterface, _, httpClientListener, httpClient, logger := testutils.SetupMockEnvironment(ctx, t, tc.conf, nil, nil)

			httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			t.Cleanup(func() {
				managementInterfaceConn.Close()
				openVPNClient.Shutdown(t.Context())

				select {
				case err := <-errOpenVPNClientCh:
					require.NoError(t, err)
				case <-time.After(1 * time.Second):
					t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
				}
			})

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

			listen, err := testutils.WaitUntilListening(t, httpClientListener.Listener.Addr().Network(), httpClientListener.Listener.Addr().String())
			if err != nil {
				return
			}

			require.NoError(t, listen.Close())

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, httpClientListener.URL+"/ready", nil)
			require.NoError(t, err)

			resp, err := httpClient.Do(request) //nolint:bodyclose
			require.NoError(t, err)

			require.Equal(t, http.StatusOK, resp.StatusCode)

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)

			err = resp.Body.Close()
			require.NoError(t, err)

			var session string

			switch {
			case tc.invalidState:
				session = invalid
			case tc.state == (state.State{}):
				session = ""
			default:
				session, err = tc.state.Encode(conf.HTTP.Secret.String())
				require.NoError(t, err)
			}

			urlPath := "/oauth2/start?state="
			if conf.HTTP.ShortURL {
				urlPath = "/?s="
			}

			request, err = http.NewRequestWithContext(t.Context(), http.MethodGet,
				fmt.Sprintf("%s%s%s", httpClientListener.URL, urlPath, session),
				nil,
			)

			require.NoError(t, err)

			if conf.HTTP.ShortURL {
				resp, err = httpClient.Do(request) //nolint:bodyclose
				require.NoError(t, err)

				_, err = io.Copy(io.Discard, resp.Body)
				require.NoError(t, err)

				err = resp.Body.Close()
				require.NoError(t, err)

				require.Equal(t, http.StatusFound, resp.StatusCode)
				require.NotEmpty(t, resp.Header.Get("Location"))

				request, err = http.NewRequestWithContext(t.Context(), http.MethodGet,
					httpClientListener.URL+resp.Header.Get("Location"),
					nil,
				)
				require.NoError(t, err)
			}

			if tc.xForwardedFor != "" {
				request.Header.Set("X-Forwarded-For", tc.xForwardedFor)
			}

			reqErrCh := make(chan error, 1)

			go func() {
				var err error

				resp, err = httpClient.Do(request) //nolint:bodyclose
				reqErrCh <- err
			}()

			if !tc.preAllow {
				testutils.ExpectMessage(t, managementInterfaceConn, reader, `client-deny 0 1 "client rejected: http client ip 127.0.0.1 and vpn ip 127.0.0.2 is different"`)
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-deny command succeeded")
			}

			select {
			case err := <-reqErrCh:
				require.NoError(t, err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for request to finish. Logs:\n\n%s", logger.String())
			}

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)

			err = resp.Body.Close()
			require.NoError(t, err)

			if tc.state == (state.State{}) {
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)

				return
			}

			if !tc.preAllow {
				require.Equal(t, http.StatusForbidden, resp.StatusCode)

				return
			}

			require.Equal(t, http.StatusFound, resp.StatusCode, logger.String())
			require.NotEmpty(t, resp.Header.Get("Set-Cookie"))
			require.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=185")
			require.NotEmpty(t, resp.Header.Get("Location"))

			httpClient.CheckRedirect = nil

			request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, resp.Header.Get("Location"), nil)
			require.NoError(t, err)

			go func() {
				var err error

				resp, err = httpClient.Do(request) //nolint:bodyclose
				reqErrCh <- err
			}()

			clientConfigSelectorActive := conf.OpenVPN.ClientConfig.Enabled && conf.OpenVPN.ClientConfig.TokenClaim != invalid &&
				(len(tc.conf.OpenVPN.ClientConfig.UserSelector.StaticValues) > 1 ||
					(len(tc.conf.OpenVPN.ClientConfig.UserSelector.StaticValues) >= 1 && conf.OpenVPN.ClientConfig.TokenClaim != ""))

			switch {
			case !tc.postAllow:
				testutils.ExpectMessage(t, managementInterfaceConn, reader, `client-deny 0 1 "client rejected"`)
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-deny command succeeded")
			case tc.state.Client.UsernameIsDefined == 1:
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth-nt 0 1")
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
			case clientConfigSelectorActive:
				// Expect profile selection
			case conf.OpenVPN.ClientConfig.Enabled:
				if tc.state.Client.CommonName == "name" {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\n"+
						"push \"ping 60\"\r\n"+
						"push \"ping-restart 180\"\r\n"+
						"push \"ping-timer-rem\" 0\r\n"+
						"push \"auth-token-user bmFtZQ==\"\r\n"+
						"END")
					testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
				} else {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\npush \"auth-token-user Y2xpZW50\"\r\nEND")
					testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
				}
			default:
				if conf.OAuth2.UserInfo {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\npush \"auth-token-user dGVzdC11c2VyQGxvY2FsaG9zdA==\"\r\nEND")
				} else {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\npush \"auth-token-user bmFtZQ==\"\r\nEND")
				}

				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
			}

			select {
			case err := <-reqErrCh:
				require.NoError(t, err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for request to finish. Logs:\n\n%s", logger.String())
			}

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			err = resp.Body.Close()
			require.NoError(t, err)

			if !tc.postAllow {
				require.Equal(t, http.StatusForbidden, resp.StatusCode, logger.GetLogs(), string(body))

				return
			}

			require.Equal(t, http.StatusOK, resp.StatusCode, logger.GetLogs(), string(body))

			require.NotEmpty(t, resp.Header.Get("Set-Cookie"))
			require.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=0")

			switch {
			case clientConfigSelectorActive:
				require.Contains(t, string(body), "Please select your client configuration profile")

				reInput := regexp.MustCompile(`type="(?:hidden|submit)" name="([^"]+)" value="([^"]+)">`)

				matches := reInput.FindAllStringSubmatch(string(body), -1)
				require.NotEmpty(t, matches, "no input fields found in profile selection form")

				fields := make(map[string]string)

				for _, match := range matches {
					require.Len(t, match, 3, string(body))

					fields[match[1]] = match[2]
				}

				require.Contains(t, fields, "token")

				request, err = http.NewRequestWithContext(t.Context(), http.MethodPost,
					httpClientListener.URL+"/oauth2/profile-submit",
					strings.NewReader(fmt.Sprintf("token=%s&profile=%s",
						url.QueryEscape(fields["token"]),
						url.QueryEscape(fields["profile"]),
					)),
				)

				require.NoError(t, err)

				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				go func() {
					var err error

					resp, err = httpClient.Do(request) //nolint:bodyclose
					reqErrCh <- err
				}()

				testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\n"+
					"push \"ping 60\"\r\n"+
					"push \"ping-restart 180\"\r\n"+
					"push \"ping-timer-rem\" 0\r\n"+
					"push \"auth-token-user bmFtZQ==\"\r\n"+
					"END")
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")

				select {
				case err := <-reqErrCh:
					require.NoError(t, err)
				case <-time.After(1 * time.Second):
					t.Fatalf("timeout waiting for request to finish. Logs:\n\n%s", logger.String())
				}

				body, err = io.ReadAll(resp.Body)
				require.NoError(t, err)

				err = resp.Body.Close()
				require.NoError(t, err)

				require.Equal(t, http.StatusOK, resp.StatusCode, logger.GetLogs())
				require.Contains(t, string(body), "Access granted")
			case conf.HTTP.Template != config.Defaults.HTTP.Template:
				require.Contains(t, string(body), "Permission is hereby granted")
			default:
				require.Contains(t, string(body), "Access granted")
			}
		})
	}
}

func TestOAuth2ProfileSubmit(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		conf          config.Config
		req           func(t *testing.T) *http.Request
		expectedError string
	}{
		{
			"missing token",
			config.Defaults,
			func(t *testing.T) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth2/profile-submit", nil)
				require.NoError(t, err)

				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			"token is empty",
		},
		{
			"invalid encrypted token",
			config.Defaults,
			func(t *testing.T) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth2/profile-submit",
					strings.NewReader("token="+url.QueryEscape("-")))

				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			"base64 decode -",
		},
		{
			"invalid token content",
			config.Defaults,

			func(t *testing.T) *http.Request {
				t.Helper()

				token := fmt.Sprintf("%d -", time.Now().Unix())

				encryptedToken, err := crypto.EncryptBytesAES([]byte(token), testutils.Secret)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth2/profile-submit",
					strings.NewReader("token="+url.QueryEscape(base64.URLEncoding.EncodeToString(encryptedToken))))
				require.NoError(t, err)

				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			"unable to parse token",
		},
		{
			"empty token content",
			config.Defaults,
			func(t *testing.T) *http.Request {
				t.Helper()

				token := fmt.Sprintf(`%d {}`, time.Now().Unix())

				encryptedToken, err := crypto.EncryptBytesAES([]byte(token), testutils.Secret)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth2/profile-submit",
					strings.NewReader("token="+url.QueryEscape(base64.URLEncoding.EncodeToString(encryptedToken))))

				require.NoError(t, err)

				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			"Invalid State: decrypt aes",
		},
		{
			"no refresh token in storage",
			config.Defaults,
			func(t *testing.T) *http.Request {
				t.Helper()

				sessionState := state.New(state.ClientIdentifier{CID: 1, KID: 2}, "127.0.0.1", "12345", "")

				encryptedState, err := sessionState.Encode(testutils.Secret)
				require.NoError(t, err)

				token := fmt.Sprintf(`%d {"state": %q}`, time.Now().Unix(), encryptedState)

				encryptedToken, err := crypto.EncryptBytesAES([]byte(token), testutils.Secret)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth2/profile-submit",
					strings.NewReader("token="+url.QueryEscape(base64.URLEncoding.EncodeToString(encryptedToken))))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			"unable to retrieve refresh token from storage: value does not exist",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			_, openVPNClient, managementInterface, _, httpClientListener, httpClient, logger := testutils.SetupMockEnvironment(ctx, t, tc.conf, nil, nil)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			t.Cleanup(func() {
				managementInterfaceConn.Close()
				openVPNClient.Shutdown(t.Context())

				select {
				case err := <-errOpenVPNClientCh:
					require.NoError(t, err)
				case <-time.After(1 * time.Second):
					t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
				}
			})

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

			listen, err := testutils.WaitUntilListening(t, httpClientListener.Listener.Addr().Network(), httpClientListener.Listener.Addr().String())
			if err != nil {
				return
			}

			require.NoError(t, listen.Close())

			request := tc.req(t)
			request.URL.Host = strings.Replace(httpClientListener.URL, "http://", "", 1)
			request.URL.Scheme = "http"

			resp, err := httpClient.Do(request)
			require.NoError(t, err)

			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			require.Contains(t, logger.String(), tc.expectedError)

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)

			err = resp.Body.Close()
			require.NoError(t, err)
		})
	}
}
