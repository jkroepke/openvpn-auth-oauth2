// Package openvpn_auth_oauth2 defines the native Go values exposed to CEL expressions.
package openvpn_auth_oauth2

import (
	celtypes "cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
)

// AuthContext contains authentication-specific CEL values.
type AuthContext struct {
	Mode *string `cel:"mode"`
}

// OpenVPNContext contains OpenVPN session-specific CEL values.
type OpenVPNContext struct {
	CommonName   *string `cel:"commonName"`
	IP           *string `cel:"ip"`
	SessionState *string `cel:"sessionState"`
}

// TokenContext contains OAuth2 token-specific CEL values.
type TokenContext struct {
	Claims Claims  `cel:"claims"`
	IP     *string `cel:"ip"`
}

// Claims adapts dynamic token claims through CEL-Go's native map implementation.
// NativeTypes does not infer map[string]any as map<string, dyn> directly.
type Claims struct {
	traits.Mapper
}

// NewClaims adapts token claims to CEL's map<string, dyn> value.
func NewClaims(claims map[string]any) Claims {
	return Claims{
		Mapper: celtypes.NewStringInterfaceMap(celtypes.DefaultTypeAdapter, claims),
	}
}

// Type reports the map type to NativeTypes while the embedded mapper implements
// the remaining CEL map operations.
func (Claims) Type() ref.Type {
	return celtypes.NewMapType(celtypes.StringType, celtypes.DynType)
}

// UserContext contains normalized user-specific CEL values.
type UserContext struct {
	Email    *string  `cel:"email"`
	Subject  *string  `cel:"subject"`
	Username *string  `cel:"username"`
	Groups   []string `cel:"groups"`
	Roles    []string `cel:"roles"`
}
