package httpserver_test

import (
	"errors"
	gohttp "net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/madflojo/testcerts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPServer(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	cert, key, err := testcerts.GenerateCertsToTempFile("/tmp/")
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
					BaseURL: &url.URL{Scheme: "http", Host: "127.0.0.1"},
					Listen:  "127.0.0.1:0",
				},
			},
			nil,
		},
		{
			"https listener invalid",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "127.0.0.1"},
					Listen:  "127.0.0.1:0",
					TLS:     true,
				},
			},
			errors.New("ListenAndServeTLS: open : no such file or directory"),
		},
		{
			"https listener",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  &url.URL{Scheme: "http", Host: "127.0.0.1"},
					Listen:   "127.0.0.1:0",
					TLS:      true,
					KeyFile:  key,
					CertFile: cert,
				},
			},
			nil,
		},
	}

	for _, tt := range confs {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mux := gohttp.NewServeMux()
			mux.Handle("/", gohttp.NotFoundHandler())

			svr := httpserver.NewHTTPServer(logger, tt.conf, mux)

			wg := sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()

				err := svr.Listen()

				if tt.err == nil {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					assert.Equal(t, tt.err.Error(), err.Error())
				}
			}()

			time.Sleep(50 * time.Millisecond)

			require.NoError(t, svr.Shutdown())
			wg.Wait()
		})
	}
}
