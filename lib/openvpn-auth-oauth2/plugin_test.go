package main

import (
	"testing"

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
