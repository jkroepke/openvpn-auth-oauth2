package utils

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

// TransformCommonName returns the common name according to the provided mode.
// If mode is CommonNameModePlain the original name is returned, otherwise
// CommonNameModeOmitValue is returned.
func TransformCommonName(mode config.OpenVPNCommonNameMode, commonName string) string {
	switch mode {
	case config.CommonNameModePlain:
		return commonName
	case config.CommonNameModeOmit:
		fallthrough
	default:
		return config.CommonNameModeOmitValue
	}
}
