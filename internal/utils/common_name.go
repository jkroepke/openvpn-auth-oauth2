package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

func TransformCommonName(mode config.OpenVPNCommonNameMode, commonName string) string {
	switch mode {
	case config.CommonNameModePlain:
		return commonName
	case config.CommonNameModeMD5:
		return fmt.Sprintf("%x", md5.Sum([]byte(commonName)))
	case config.CommonNameModeSHA1:
		return fmt.Sprintf("%x", sha1.Sum([]byte(commonName)))
	case config.CommonNameModeOmit:
		fallthrough
	default:
		return config.CommonNameModeOmitValue
	}
}
