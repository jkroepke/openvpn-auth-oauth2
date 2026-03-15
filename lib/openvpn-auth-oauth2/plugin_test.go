//go:build (linux || openbsd || freebsd) && cgo

package main

import (
	"testing"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/openvpn"
	"github.com/stretchr/testify/require"
)

func TestMinVersionRequired(t *testing.T) {
	t.Parallel()

	require.Equal(t, openvpn.PluginVerMin, int(openvpn_plugin_min_version_required_v1()))
}

func TestSelectInitializationPoint(t *testing.T) {
	t.Parallel()

	require.Equal(t, c.OpenVPNPluginInitPreDaemon, int(openvpn_plugin_select_initialization_point_v1()))
}

func TestPluginInvalidHandle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		fn   func()
	}{
		{
			"openvpn_plugin_func_v3_go_struct_ver_0",
			func() {
				openvpn_plugin_func_v3_go(0, nil, nil)
			},
		},
		{
			"openvpn_plugin_func_v3_go_args_nil",
			func() {
				openvpn_plugin_func_v3_go(5, nil, nil)
			},
		},
		{
			"openvpn_plugin_func_v3_go_ret_nil",
			func() {
				openvpn_plugin_func_v3_go(5,
					unsafe.Pointer(&c.OpenVPNPluginArgsFuncIn{
						Handle: nil,
					}),
					nil)
			},
		},
		{
			"openvpn_plugin_func_v3_go_handle_nil",
			func() {
				openvpn_plugin_func_v3_go(openvpn.PluginStructVerMin,
					unsafe.Pointer(&c.OpenVPNPluginArgsFuncIn{
						Handle: nil,
					}),
					unsafe.Pointer(&c.OpenVPNPluginArgsFuncReturn{}),
				)
			},
		},
		{
			"openvpn_plugin_close_v1",
			func() {
				openvpn_plugin_close_v1(nil)
			},
		},
		{
			"openvpn_plugin_client_constructor_v1",
			func() {
				openvpn_plugin_client_constructor_v1(nil)
			},
		},
		{
			"openvpn_plugin_client_destructor_v1",
			func() {
				openvpn_plugin_client_destructor_v1(nil, nil)
			},
		},
		{
			"openvpn_plugin_abort_v1",
			func() {
				openvpn_plugin_abort_v1(nil)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				tc.fn()
			})
		})
	}
}
