package testsuite

import (
	"reflect"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/stretchr/testify/require"
)

// SetupSSFTransmitter starts a mock SSF transmitter and enables SSF in the
// suite configuration with its issuer and poll token. An SSF block that was
// left empty gets the defaults first.
func (s *Suite) SetupSSFTransmitter(tb testing.TB, opts ...ssftest.Option) *ssftest.Transmitter {
	tb.Helper()

	transmitter := ssftest.New(tb, opts...)

	issuer, err := types.NewURL(transmitter.Issuer())
	require.NoError(tb, err)

	if reflect.ValueOf(s.conf.SSF).IsZero() {
		s.conf.SSF = config.Defaults.SSF
	}

	s.conf.SSF.Enabled = true
	s.conf.SSF.Issuer = issuer
	s.conf.SSF.Poll.Token = types.Secret(transmitter.Token())

	return transmitter
}
