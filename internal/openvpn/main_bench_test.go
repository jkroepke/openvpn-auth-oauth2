package openvpn //nolint:testpackage

import "testing"

func BenchmarkManagementCommandName(b *testing.B) {
	const command = "client-pending-auth 123 456 \"WEB_AUTH::https://example.com/oauth2/start\" 300\r\n"

	var name string

	b.ReportAllocs()

	for b.Loop() {
		name = managementCommandName(command)
	}

	if name != "client-pending-auth" {
		b.Fatalf("unexpected command name %q", name)
	}
}
