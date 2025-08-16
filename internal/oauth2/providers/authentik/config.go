package authentik

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
)

// GetProviderConfig implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p Provider) GetProviderConfig() (types.ProviderConfig, error) {
	return p.Provider.GetProviderConfig()
}