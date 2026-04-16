package oauth2_test

import (
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
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
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
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.1", IPPort: "12345"},
			false,
			"",
			true,
			true,
		},
		{
			"with username defined",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, UsernameIsDefined: 1, CommonName: "name"}, IPAddr: "127.0.0.1", IPPort: "12345"},
			false,
			"",
			true,
			true,
		},
		{
			"with acr values",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Acr = []string{"phr"}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.Nonce = true
				conf.OAuth2.PKCE = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.1", IPPort: "12345"},
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
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = false
				conf.HTTP.Template = tmpl
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.1", IPPort: "12345"},
			false,
			"",
			true,
			true,
		},
		{
			"with userinfo enabled",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = []string{"group1"}
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.UserInfo = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.1", IPPort: "12345"},
			false,
			"",
			true,
			true,
		},
		{
			"with userinfo enabled + validate groups",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = []string{"group0", "group1"}
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.UserInfo = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.1", IPPort: "12345"},
			false,
			"",
			true,
			true,
		},
		{
			"with userinfo enabled + missing validate groups",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = []string{"group0"}
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.UserInfo = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.1", IPPort: "12345"},
			false,
			"",
			true,
			false,
		},
		{
			"with ipaddr",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.1", IPPort: "12345"},
			false,
			"",
			true,
			true,
		},
		{
			"with short-url",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.ShortURL = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.1", IPPort: "12345"},
			false,
			"",
			true,
			true,
		},
		{
			"with ipaddr + forwarded-for",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2",
			true,
			true,
		},
		{
			"with ipaddr + disabled forwarded-for",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = false
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2",
			false,
			false,
		},
		{
			"with ipaddr + multiple forwarded-for",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with cel validation result false",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.Validate.CEL = "false"
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			false,
		},
		{
			"with client config found",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"id1.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config and custom claim",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.TokenClaim = testsuite.SubjectClaim
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"id1.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config not found",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = ""
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{},
				}

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "client"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim
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
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values + claim string",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"static"}
				conf.OpenVPN.ClientConfig.TokenClaim = testsuite.SubjectClaim
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"id1.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values + claim array",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim
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
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values + claim invalid",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim
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
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + static values + not found",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = ""
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
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "client"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config selector + multiple static values",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim
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
			state.State{Client: state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, IPAddr: "127.0.0.2", IPPort: "12345"},
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with empty state",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

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
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.OpenVPNUsernameClaim = testsuite.SubjectClaim

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

			suite := testsuite.New(tc.conf)
			suite.SetupMockEnvironment(ctx, t, nil)
			suite.ExpectVersionAndReleaseHold(t)

			httpClient := suite.GetHTTPClient()
			httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}

			resp, _, err := suite.DoHTTPRequest(ctx, http.MethodGet, "/ready", nil, http.NoBody) //nolint:bodyclose
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			var session string

			switch {
			case tc.invalidState:
				session = invalid
			case tc.state == (state.State{}):
				session = ""
			default:
				session, err = state.Encrypt(testsuite.Cipher, tc.state)
				require.NoError(t, err)
			}

			urlPath := "/oauth2/start?state=" + session

			if tc.conf.HTTP.ShortURL {
				resp, _, err = suite.DoHTTPRequest(ctx, http.MethodGet, "/?s="+session, nil, http.NoBody) //nolint:bodyclose
				require.NoError(t, err)

				require.Equal(t, http.StatusFound, resp.StatusCode)

				urlPath = resp.Header.Get("Location")
			}

			header := make(http.Header)

			if tc.xForwardedFor != "" {
				header.Set("X-Forwarded-For", tc.xForwardedFor)
			}

			reqErrCh := make(chan error, 1)

			go func() {
				var err error

				resp, _, err = suite.DoHTTPRequest(ctx, http.MethodGet, urlPath, header, http.NoBody) //nolint:bodyclose

				reqErrCh <- err
			}()

			if !tc.preAllow {
				suite.ExpectMessage(t, `client-deny 0 1 "client rejected: http client ip 127.0.0.1 and vpn ip 127.0.0.2 is different"`)
				suite.SendMessagef(t, `SUCCESS: client-deny command succeeded`)
			}

			select {
			case err := <-reqErrCh:
				require.NoError(t, err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for request to finish. Logs:\n\n%s", suite.Logs())
			}

			if tc.state == (state.State{}) {
				require.Equal(t, http.StatusBadRequest, resp.StatusCode, suite.Logs())

				return
			}

			if !tc.preAllow {
				require.Equal(t, http.StatusForbidden, resp.StatusCode, suite.Logs())

				return
			}

			require.Equal(t, http.StatusFound, resp.StatusCode, suite.Logs())
			require.NotEmpty(t, resp.Header.Get("Location"), "Location header is empty")
			require.NotEmpty(t, resp.Header.Get("Set-Cookie"), "Set-Cookie header is empty")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=185")

			httpClient.CheckRedirect = nil

			var body []byte

			go func() {
				var err error

				resp, body, err = suite.DoHTTPRequest(ctx, http.MethodGet, resp.Header.Get("Location"), header, http.NoBody) //nolint:bodyclose
				reqErrCh <- err
			}()

			clientConfigSelectorActive := tc.conf.OpenVPN.ClientConfig.Enabled && tc.conf.OpenVPN.ClientConfig.TokenClaim != invalid &&
				(len(tc.conf.OpenVPN.ClientConfig.UserSelector.StaticValues) > 1 ||
					(len(tc.conf.OpenVPN.ClientConfig.UserSelector.StaticValues) >= 1 && tc.conf.OpenVPN.ClientConfig.TokenClaim != ""))

			switch {
			case !tc.postAllow:
				suite.ExpectMessage(t, `client-deny 0 1 "client rejected"`)
				suite.SendMessagef(t, "SUCCESS: client-deny command succeeded")
			case tc.state.Client.UsernameIsDefined == 1:
				suite.ExpectMessage(t, "client-auth-nt 0 1")
				suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")
			case clientConfigSelectorActive:
				// Expect profile selection
			case tc.conf.OpenVPN.ClientConfig.Enabled:
				if tc.state.Client.CommonName == "name" {
					suite.ExpectMessage(t, "client-auth 0 1\r\n"+
						"push \"ping 60\"\r\n"+
						"push \"ping-restart 180\"\r\n"+
						"push \"ping-timer-rem\" 0\r\n"+
						"push \"auth-token-user aWQx\"\r\n"+
						"END")
					suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")
				} else {
					suite.ExpectMessage(t, "client-auth 0 1\r\npush \"auth-token-user Y2xpZW50\"\r\nEND")
					suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")
				}
			default:
				if tc.conf.OAuth2.UserInfo {
					suite.ExpectMessage(t, "client-auth 0 1\r\npush \"auth-token-user dGVzdC11c2VyQGxvY2FsaG9zdA==\"\r\nEND")
				} else {
					suite.ExpectMessage(t, "client-auth 0 1\r\npush \"auth-token-user aWQx\"\r\nEND")
				}

				suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")
			}

			select {
			case err := <-reqErrCh:
				require.NoError(t, err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for request to finish. Logs:\n\n%s", suite.Logs())
			}

			if !tc.postAllow {
				require.Equal(t, http.StatusForbidden, resp.StatusCode, suite.Logs(), string(body))

				return
			}

			require.Equal(t, http.StatusOK, resp.StatusCode, suite.Logs(), string(body))

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

				header := make(http.Header)
				header.Set("Content-Type", "application/x-www-form-urlencoded")

				var body []byte

				go func() {
					var err error

					//nolint:bodyclose
					resp, body, err = suite.DoHTTPRequest(ctx, http.MethodPost,
						"/oauth2/profile-submit",
						header,
						strings.NewReader(fmt.Sprintf("token=%s&profile=%s",
							url.QueryEscape(fields["token"]),
							url.QueryEscape(fields["profile"]),
						)))

					reqErrCh <- err
				}()

				suite.ExpectMessage(t, "client-auth 0 1\r\n"+
					"push \"ping 60\"\r\n"+
					"push \"ping-restart 180\"\r\n"+
					"push \"ping-timer-rem\" 0\r\n"+
					"push \"auth-token-user aWQx\"\r\n"+
					"END")
				suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

				select {
				case err := <-reqErrCh:
					require.NoError(t, err)
				case <-time.After(1 * time.Second):
					t.Fatalf("timeout waiting for request to finish. Logs:\n\n%s", suite.Logs())
				}

				require.Equal(t, http.StatusOK, resp.StatusCode, suite.Logs())
				require.Contains(t, string(body), "Access granted")
			case tc.conf.HTTP.Template != config.Defaults.HTTP.Template:
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
			"illegal base64 data at input",
		},
		{
			"invalid token content",
			config.Defaults,

			func(t *testing.T) *http.Request {
				t.Helper()

				token := fmt.Sprintf("%d -", time.Now().Unix())

				encryptedToken, err := testsuite.Cipher.EncryptBytes([]byte(token))
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

				encryptedToken, err := testsuite.Cipher.EncryptBytes([]byte(token))
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth2/profile-submit",
					strings.NewReader("token="+url.QueryEscape(base64.URLEncoding.EncodeToString(encryptedToken))))

				require.NoError(t, err)

				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			"Invalid State: decrypt state: ciphertext block size is too short",
		},
		{
			"no refresh token in storage",
			config.Defaults,
			func(t *testing.T) *http.Request {
				t.Helper()

				sessionState := state.State{Client: state.ClientIdentifier{CID: 1, KID: 2}, IPAddr: "127.0.0.1", IPPort: "12345"}

				encryptedState, err := state.Encrypt(testsuite.Cipher, sessionState)
				require.NoError(t, err)

				token := fmt.Sprintf(`%d {"state": %q}`, time.Now().Unix(), encryptedState)

				encryptedToken, err := testsuite.Cipher.EncryptBytes([]byte(token))
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

			suite := testsuite.New(tc.conf)
			suite.SetupMockEnvironment(ctx, t, nil)
			suite.ExpectVersionAndReleaseHold(t)

			httpClient := suite.GetHTTPClient()

			request := tc.req(t)
			request.URL.Host = strings.Replace(suite.GetHTTPServerURL(), "http://", "", 1)
			request.URL.Scheme = "http"

			resp, err := httpClient.Do(request)
			require.NoError(t, err)

			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			require.Contains(t, suite.Logs(), tc.expectedError)

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)

			err = resp.Body.Close()
			require.NoError(t, err)
		})
	}
}

func TestOAuth2Callback(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		conf           config.Config
		req            func(t *testing.T) *http.Request
		expectedStatus int
		expectedError  string
	}{
		{
			"empty state",
			config.Defaults,
			func(t *testing.T) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/oauth2/callback", nil)
				require.NoError(t, err)

				return req
			},
			http.StatusBadRequest,
			"state is empty",
		},
		{
			"invalid state",
			config.Defaults,
			func(t *testing.T) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/oauth2/callback?state=invalid", nil)
				require.NoError(t, err)

				return req
			},
			http.StatusBadRequest,
			"illegal base64 data",
		},
		{
			"invalid state",
			config.Defaults,
			func(t *testing.T) *http.Request {
				t.Helper()

				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/oauth2/callback?state="+base64.URLEncoding.EncodeToString([]byte("invalid")), nil)
				require.NoError(t, err)

				return req
			},
			http.StatusBadRequest,
			"ciphertext block size is too short",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			suite := testsuite.New(tc.conf)
			suite.SetupMockEnvironment(ctx, t, nil)
			suite.ExpectVersionAndReleaseHold(t)

			httpClient := suite.GetHTTPClient()

			request := tc.req(t)
			request.URL.Host = strings.Replace(suite.GetHTTPServerURL(), "http://", "", 1)
			request.URL.Scheme = "http"

			resp, err := httpClient.Do(request)
			require.NoError(t, err)

			require.Equal(t, tc.expectedStatus, resp.StatusCode)
			require.Contains(t, suite.Logs(), tc.expectedError)

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)

			err = resp.Body.Close()
			require.NoError(t, err)
		})
	}
}
