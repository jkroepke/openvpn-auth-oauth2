package utils_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestTransformCommonName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		mode     config.OpenVPNCommonNameMode
		expected string
		actual   string
	}{
		{
			config.CommonNameModePlain,
			"hello world",
			"hello world",
		},
		{
			config.CommonNameModeMD5,
			"5eb63bbbe01eeed093cb22bb8f5acdc3",
			"hello world",
		},
		{
			config.CommonNameModeSHA1,
			"2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
			"hello world",
		},
		{
			config.CommonNameModeOmit,
			config.CommonNameModeOmitValue,
			"hello world",
		},
	} {
		tc := tc

		t.Run(tc.mode.String(), func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, utils.TransformCommonName(tc.mode, tc.actual))
		})
	}
}
