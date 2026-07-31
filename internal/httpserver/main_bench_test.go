package httpserver_test

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/httpserver"
)

func BenchmarkNewHTTPServer(b *testing.B) {
	logger := slog.New(slog.DiscardHandler)
	mux := http.NewServeMux()
	conf := config.HTTP{Listen: "127.0.0.1:9000"}

	var server *httpserver.Server

	b.ReportAllocs()

	for b.Loop() {
		server = httpserver.NewHTTPServer(httpserver.ServerNameDefault, logger, conf, mux)
	}

	_ = server
}

func BenchmarkGetCertificate(b *testing.B) {
	server := httpserver.NewHTTPServer(
		httpserver.ServerNameDefault,
		slog.New(slog.DiscardHandler),
		config.HTTP{},
		http.NewServeMux(),
	)
	getCertificate := server.GetCertificateFunc()

	var (
		certificate *tls.Certificate
		err         error
	)

	b.ReportAllocs()

	for b.Loop() {
		certificate, err = getCertificate(nil)
		if err != nil {
			b.Fatal(err)
		}
	}

	_ = certificate
}
