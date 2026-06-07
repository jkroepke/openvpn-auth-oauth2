// Package testsuite provides integration-test helpers for OpenVPN management,
// OAuth2, OIDC, and HTTP test flows.
//
// The central type is Suite, which owns test configuration, mock HTTP
// transport, in-memory logs, the OpenVPN client, the OAuth2 client, and the
// accepted management-interface connection. Suite can set up either a full mock
// OIDC environment with an HTTP callback server or a lighter management-only
// environment for OpenVPN tests.
//
// SetupOIDCServer starts a minimal OIDC provider and applies the generated
// issuer, client credentials, callback base URL, nonce settings, and refresh
// defaults to the suite configuration. SetupOpenVPNOAuth2Clients then builds the
// OpenVPN and OAuth2 clients from that configuration.
//
// Conn wraps a raw net.Conn with the same management-interface assertions used
// by Suite, so tests that do not need a full Suite can still send commands,
// compare responses, read single lines, and perform the OpenVPN version and
// hold-release handshake consistently.
//
// The package also includes HTTP helpers for issuing requests through either a
// Suite-owned client or an arbitrary http.Client, plus mock round-trippers and
// listener utilities used by integration tests. Logger and buffer primitives
// live in internal/test/testlogger; Suite exposes only GetLogger and Logs for
// consumers that need log output.
package testsuite
