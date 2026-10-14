package testsuite_test

import (
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupSSFTransmitter(t *testing.T) {
	t.Parallel()

	t.Run("applies defaults", func(t *testing.T) {
		t.Parallel()

		conf := &config.Config{}
		transmitter := testsuite.New(conf).SetupSSFTransmitter(t, ssftest.WithToken("token"))

		require.True(t, conf.SSF.Enabled)
		assert.Equal(t, transmitter.Issuer(), conf.SSF.Issuer.String())
		assert.Equal(t, "token", conf.SSF.Poll.Token.String())
		assert.Equal(t, config.Defaults.SSF.Poll.Interval, conf.SSF.Poll.Interval)
		assert.Equal(t, config.SchemeHTTPS, conf.SSFIssuer().Scheme)
	})

	t.Run("keeps configured values", func(t *testing.T) {
		t.Parallel()

		conf := &config.Config{SSF: config.SSF{Poll: config.SSFPoll{Interval: time.Second}}}
		testsuite.New(conf).SetupSSFTransmitter(t)

		assert.Equal(t, time.Second, conf.SSF.Poll.Interval)
		assert.Equal(t, ssftest.DefaultToken, conf.SSF.Poll.Token.String())
	})
}
