package utils_test

import (
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

type benchmarkRoundTripper struct{}

func (benchmarkRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func BenchmarkUserAgentTransportRoundTrip(b *testing.B) {
	transport := utils.NewUserAgentTransport(benchmarkRoundTripper{})

	req, err := http.NewRequestWithContext(b.Context(), http.MethodGet, "http://localhost", nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		req.Header = make(http.Header)

		resp, err := transport.RoundTrip(req)
		if err != nil {
			b.Fatal(err)
		}

		if err = resp.Body.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLookupGroupNumeric(b *testing.B) {
	var gid int

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		parsedGID, err := utils.LookupGroup("1001")
		if err != nil {
			b.Fatal(err)
		}

		gid = parsedGID
	}

	_ = gid
}

func BenchmarkTransformCommonName(b *testing.B) {
	for _, tc := range []struct {
		name string
		mode config.OpenVPNCommonNameMode
	}{
		{
			name: "plain",
			mode: config.CommonNameModePlain,
		},
		{
			name: "omit",
			mode: config.CommonNameModeOmit,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var commonName string

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				commonName = utils.TransformCommonName(tc.mode, "test-client@example.com")
			}

			_ = commonName
		})
	}
}
