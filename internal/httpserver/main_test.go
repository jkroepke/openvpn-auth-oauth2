package httpserver_test

import (
	"context"
	"crypto/tls"
	"errors"
	gohttp "net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httpserver"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testlogger"
	"github.com/madflojo/testcerts"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPServer(t *testing.T) {
	t.Parallel()

	logger := testlogger.New()

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

			svr := httpserver.NewHTTPServer(httpserver.ServerNameDefault, logger.Logger(), tc.conf.HTTP, mux)

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

func TestGetCertificateFuncAndReload(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certFile, keyFile := generateCertificateFiles(t, tempDir)

	conf := config.HTTP{
		TLS:      true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	server := httpserver.NewHTTPServer(
		httpserver.ServerNameDefault,
		testlogger.New().Logger(),
		conf,
		gohttp.NewServeMux(),
	)
	getCertificate := server.GetCertificateFunc()

	certificate, err := getCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Nil(t, certificate)

	require.NoError(t, server.Reload(t.Context()))

	firstCertificate, err := getCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, firstCertificate)
	require.NotEmpty(t, firstCertificate.Certificate)

	replacementCertFile, replacementKeyFile := generateCertificateFiles(t, tempDir)
	replaceFile(t, replacementCertFile, certFile)
	replaceFile(t, replacementKeyFile, keyFile)

	require.NoError(t, server.Reload(t.Context()))

	reloadedCertificate, err := getCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, reloadedCertificate)
	require.NotEqual(t, firstCertificate.Certificate[0], reloadedCertificate.Certificate[0])

	require.NoError(t, os.Remove(certFile))

	err = server.Reload(t.Context())
	require.ErrorContains(t, err, "tls.LoadX509KeyPair")

	preservedCertificate, err := getCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, reloadedCertificate.Certificate[0], preservedCertificate.Certificate[0])
}

func TestReloadDoesNothingWhenTLSDisabled(t *testing.T) {
	t.Parallel()

	server := httpserver.NewHTTPServer(
		httpserver.ServerNameDefault,
		testlogger.New().Logger(),
		config.HTTP{},
		gohttp.NewServeMux(),
	)

	require.NoError(t, server.Reload(t.Context()))

	certificate, err := server.GetCertificateFunc()(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Nil(t, certificate)
}

func generateCertificateFiles(tb testing.TB, dir string) (string, string) {
	tb.Helper()

	certFile, keyFile, err := testcerts.GenerateCertsToTempFile(dir)
	require.NoError(tb, err)

	return certFile, keyFile
}

func replaceFile(tb testing.TB, source, destination string) {
	tb.Helper()

	body, err := os.ReadFile(source)
	require.NoError(tb, err)

	require.NoError(tb, os.WriteFile(destination, body, 0o600))
	require.NoError(tb, os.Remove(source))
}
