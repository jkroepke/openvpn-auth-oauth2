package config

import (
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
)

type secretFlagValue struct {
	target *types.Secret
}

func newSecretFlagValue(target *types.Secret) *secretFlagValue {
	return &secretFlagValue{target: target}
}

func (s *secretFlagValue) Set(value string) error {
	if err := s.target.UnmarshalText([]byte(value)); err != nil {
		return fmt.Errorf("set secret flag: %w", err)
	}

	return nil
}

func (s *secretFlagValue) String() string {
	return ""
}
