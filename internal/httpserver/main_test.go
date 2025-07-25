package httpserver_test

import (
	"context"
	"errors"
	gohttp "net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/madflojo/testcerts"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPServer(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	cert, key, err := testcerts.GenerateCertsToTempFile(os.TempDir())
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, os.Remove(key))
		require.NoError(t, os.Remove(cert))
	})

	confs := []struct {
		name string
		conf config.Config
		err  error
	}{
		{
			"http listener",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "127.0.0.1"}},
					Listen:  "127.0.0.1:0",
				},
			},
			nil,
		},
		{
			"https listener invalid",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "127.0.0.1"}},
					Listen:  "127.0.0.1:0",
					TLS:     true,
				},
			},
			errors.New("tls.LoadX509KeyPair: open"),
		},
		{
			"https listener",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "127.0.0.1"}},
					Listen:   "127.0.0.1:0",
					TLS:      true,
					KeyFile:  key,
					CertFile: cert,
				},
			},
			nil,
		},
	}

	for _, tc := range confs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mux := gohttp.NewServeMux()
			mux.Handle("/", gohttp.NotFoundHandler())

			svr := httpserver.NewHTTPServer(httpserver.ServerNameDefault, logger.Logger, tc.conf.HTTP, mux)

			ctx, cancel := context.WithCancel(t.Context())

			errCh := make(chan error, 1)

			go func() {
				errCh <- svr.Listen(ctx)
			}()

			if tc.err == nil {
				require.NoError(t, svr.Reload(t.Context()))

				time.Sleep(50 * time.Millisecond)
				cancel()

				require.NoError(t, <-errCh)
			} else {
				cancel()
				require.ErrorContains(t, <-errCh, tc.err.Error())
			}
		})
	}
}
