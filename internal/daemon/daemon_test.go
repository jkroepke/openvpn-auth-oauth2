//nolint:testpackage // Tests exercise the unexported debug listener routes.
package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/metrics"
	"github.com/stretchr/testify/require"
)

func TestDebugMuxRoutes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		pprof         bool
		metrics       bool
		metricsStatus int
		pprofStatus   int
	}{
		{"pprof only", true, false, http.StatusTemporaryRedirect, http.StatusOK},
		{"metrics only", false, true, http.StatusOK, http.StatusNotFound},
		{"pprof and metrics", true, true, http.StatusOK, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := config.Defaults
			conf.Debug.Pprof = tc.pprof
			conf.Debug.Metrics = tc.metrics

			var appMetrics *metrics.Metrics
			if tc.metrics {
				appMetrics = metrics.New("test", "none")
			}

			mux := newDebugMux(&conf, appMetrics)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
			require.Equal(t, tc.metricsStatus, rec.Code)

			if tc.metrics {
				require.Equal(t, metrics.ContentType, rec.Header().Get("Content-Type"))
				require.Contains(t, rec.Body.String(), `openvpn_auth_oauth2_build_info{version="test",commit="none",`)
			}

			rec = httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/debug/pprof/", nil))
			require.Equal(t, tc.pprofStatus, rec.Code)
		})
	}
}
