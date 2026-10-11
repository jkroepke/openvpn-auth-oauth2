package metrics_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/deny"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/metrics"
	"github.com/stretchr/testify/require"
)

func TestMetricsWrite(t *testing.T) {
	t.Parallel()

	appMetrics := metrics.New("1.2.3", "abc\"def")

	appMetrics.ClientAccepted()
	appMetrics.ClientAccepted()
	appMetrics.ClientDenied("client rejected")
	appMetrics.ClientDenied("OpenVPN Client does not support SSO authentication via webauth")
	appMetrics.ClientDenied("client rejected: http client ip 10.0.0.1 and vpn ip 10.0.0.2 is different")
	appMetrics.ClientDenied("")
	appMetrics.SilentReAuth(metrics.SilentReAuthSuccess)
	appMetrics.SilentReAuth(metrics.SilentReAuthFallback)
	appMetrics.SilentReAuth(metrics.SilentReAuthFallback)
	appMetrics.ObserveCodeExchange(300 * time.Millisecond)
	appMetrics.ObserveCommand("client-deny", 3*time.Millisecond)
	appMetrics.ObserveCommand("client-auth-nt", 20*time.Second)
	appMetrics.ClientQueued()
	appMetrics.ClientQueued()
	appMetrics.ClientDequeued()

	var buf bytes.Buffer

	require.NoError(t, appMetrics.Write(&buf))

	output := buf.String()

	for _, expected := range []string{
		`openvpn_auth_oauth2_build_info{version="1.2.3",commit="abc\"def",goversion="go`,
		"# TYPE openvpn_auth_oauth2_openvpn_client_accepted_total counter\n",
		"openvpn_auth_oauth2_openvpn_client_accepted_total 2\n",
		`openvpn_auth_oauth2_openvpn_client_denied_total{reason="client_rejected"} 1` + "\n",
		`openvpn_auth_oauth2_openvpn_client_denied_total{reason="openvpn_client_does_not_support_sso_authentication_via_webauth"} 1` + "\n",
		`openvpn_auth_oauth2_openvpn_client_denied_total{reason="other"} 2` + "\n",
		`openvpn_auth_oauth2_oauth2_silent_reauth_total{result="fallback"} 2` + "\n",
		`openvpn_auth_oauth2_oauth2_silent_reauth_total{result="success"} 1` + "\n",
		"# TYPE openvpn_auth_oauth2_oauth2_code_exchange_duration_seconds histogram\n",
		`openvpn_auth_oauth2_oauth2_code_exchange_duration_seconds_bucket{le="0.25"} 0` + "\n",
		`openvpn_auth_oauth2_oauth2_code_exchange_duration_seconds_bucket{le="0.5"} 1` + "\n",
		`openvpn_auth_oauth2_oauth2_code_exchange_duration_seconds_bucket{le="+Inf"} 1` + "\n",
		"openvpn_auth_oauth2_oauth2_code_exchange_duration_seconds_sum 0.3\n",
		"openvpn_auth_oauth2_oauth2_code_exchange_duration_seconds_count 1\n",
		`openvpn_auth_oauth2_openvpn_command_duration_seconds_bucket{command="client-deny",le="0.005"} 1` + "\n",
		`openvpn_auth_oauth2_openvpn_command_duration_seconds_count{command="client-deny"} 1` + "\n",
		`openvpn_auth_oauth2_openvpn_command_duration_seconds_bucket{command="client-auth-nt",le="10"} 0` + "\n",
		`openvpn_auth_oauth2_openvpn_command_duration_seconds_bucket{command="client-auth-nt",le="+Inf"} 1` + "\n",
		`openvpn_auth_oauth2_openvpn_command_duration_seconds_sum{command="client-auth-nt"} 20` + "\n",
		"openvpn_auth_oauth2_openvpn_client_queue_length 1\n",
	} {
		require.Contains(t, output, expected)
	}

	// Series are sorted by label value so the output is stable between scrapes.
	require.Less(t,
		strings.Index(output, `command="client-auth-nt"`),
		strings.Index(output, `command="client-deny"`),
	)
}

func TestMetricsServeHTTP(t *testing.T) {
	t.Parallel()

	appMetrics := metrics.New("dev", "none")
	appMetrics.ClientAccepted()

	rec := httptest.NewRecorder()
	appMetrics.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, metrics.ContentType, rec.Header().Get("Content-Type"))
	require.Contains(t, rec.Body.String(), "openvpn_auth_oauth2_openvpn_client_accepted_total 1\n")
}

func TestMetricsNilReceiver(t *testing.T) {
	t.Parallel()

	var appMetrics *metrics.Metrics

	require.NotPanics(t, func() {
		appMetrics.ClientAccepted()
		appMetrics.ClientDenied("client rejected")
		appMetrics.SilentReAuth(metrics.SilentReAuthError)
		appMetrics.ObserveCodeExchange(time.Second)
		appMetrics.ObserveCommand("client-deny", time.Second)
		appMetrics.ClientQueued()
		appMetrics.ClientDequeued()
	})

	var buf bytes.Buffer

	require.NoError(t, appMetrics.Write(&buf))
	require.Empty(t, buf.String())
}

func TestMetricsConcurrentUse(t *testing.T) {
	t.Parallel()

	appMetrics := metrics.New("dev", "none")

	var wg sync.WaitGroup

	for range 8 {
		wg.Go(func() {
			for range 100 {
				appMetrics.ClientAccepted()
				appMetrics.ClientDenied("client rejected")
				appMetrics.ObserveCommand("client-auth", time.Millisecond)
				_ = appMetrics.Write(&bytes.Buffer{})
			}
		})
	}

	wg.Wait()

	var buf bytes.Buffer

	require.NoError(t, appMetrics.Write(&buf))
	require.Contains(t, buf.String(), "openvpn_auth_oauth2_openvpn_client_accepted_total 800\n")
	require.Contains(t, buf.String(), `openvpn_auth_oauth2_openvpn_client_denied_total{reason="client_rejected"} 800`+"\n")
	require.Contains(t, buf.String(), `openvpn_auth_oauth2_openvpn_command_duration_seconds_count{command="client-auth"} 800`+"\n")
}

func TestMetricsClientDeniedKnowsEveryDenyReason(t *testing.T) {
	t.Parallel()

	for reason := deny.ClientRejected; reason <= deny.AcceptFailed; reason++ {
		appMetrics := metrics.New("dev", "none")
		appMetrics.ClientDenied(reason.String())

		var buf bytes.Buffer

		require.NoError(t, appMetrics.Write(&buf))
		require.NotContains(t, buf.String(), `reason="other"`, reason.String())
	}
}
