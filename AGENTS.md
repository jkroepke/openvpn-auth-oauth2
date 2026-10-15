# Agent instructions

Follow [`CONTRIBUTING.md`](CONTRIBUTING.md) for all changes. See
[`DEVELOPER.md`](DEVELOPER.md) for the architecture and `docs/` for user-facing
configuration and behavior.

## Pull request labels

Before merging, apply at least one label from [`.github/release.yml`](.github/release.yml):

- `💥 breaking-change`: breaking changes
- `✨ enhancement`: user-visible functionality
- `🐞 bug`: fixes
- `🛠️ dependencies`: dependency updates
- `📖 docs`: documentation
- `chore`: internal performance work, tests, CI, or maintenance

Add `💥 breaking-change` alongside any other applicable label. Labeling is an
AI-agent-only operation; do not tell external contributors to apply labels.

## Program overview

This Go application bridges OpenVPN's webauth protocol with OIDC providers. It
communicates with the OpenVPN management interface and serves the browser-based
authentication flow over HTTP.

## Client-visible error classification

Preserve broad failure classes without exposing implementation details:

- `client rejected`: authentication or authorization failures
- `internal error`: infrastructure or internal processing failures

Log the technical error. Browser error pages must show an opaque, log-correlated
error ID. Deny clients only with a `deny.Reason` from `internal/deny`; it derives
the `client-deny` text, HTTP status and log level, so never pass an error
message to OpenVPN. `openvpn.Client.AcceptClient` only reports errors; its
caller denies the client with `deny.ReasonOf(err, deny.AcceptFailed)`. Never classify errors by matching message strings; if upstream provides
no structured distinction, keep the generic classification. See
[issue #1121](https://github.com/jkroepke/openvpn-auth-oauth2/issues/1121).

## Plugin cgo pointer checks

Compile all tests with `GOEXPERIMENT=cgocheck2`; the `Makefile` and CI test job
already set it.
Do not try to enable it at runtime with `GODEBUG`, `//go:debug`, or `t.Setenv`.

## Encrypted-state format migrations

Only client-held OAuth state and profile-selector ciphertext can cross an
executable upgrade, and they remain active for at most five minutes. Refresh-token
ciphertext is process-local, is lost on restart, and survives only in-process
configuration reloads. Do not add refresh-token migration or background
re-encryption solely for a format change.

Switch formats directly if affected users may retry authentication. Otherwise,
temporarily read legacy ciphertext while writing the new version. Legacy reads
are needed only until five minutes after the last old instance stops issuing
ciphertext. For rolling deployments, stage the switch because old instances
cannot read the new format.

## Session registry

`internal/sessionregistry` maps accepted OpenVPN clients to the OIDC identity
(iss, sub, sid, email) they logged in with, so SSF events can be resolved to
clients. Every path that accepts a client after OIDC authentication must call
`oauth2.Client.RegisterClient` once `AcceptClient` succeeds: the OAuth2
callback, profile submit and silent re-authentication do today. Bypassed
clients are not registered. With `oauth2.refresh.validate-user=false` there is
no token on refresh, so the identity travels in the stored refresh state; keep
it there when changing that format. The registry is created in `runLoop` and
survives configuration reloads, like the refresh-token data.

## SSF event verification

`internal/ssf` verifies Security Event Tokens and must not import OpenVPN
packages. `Verifier.Verify` does not record the `jti`; call
`Verifier.Processed` only after the revocation was enforced, otherwise a SET
whose enforcement failed is rejected as a replay when the transmitter
redelivers it. `ssf.Receiver` follows that rule: it acknowledges a
SET only after the handler succeeded, reports failed verification in
`setErrs`, and leaves a SET unacknowledged when the handler fails so the
transmitter redelivers it. The receiver is wired in `daemon.setupSSFReceiver`;
discovery errors stop the startup on purpose. Verification errors are `*ssf.Error` values carrying the RFC 8935
code for `setErrs`. Signature checks go through zitadel/oidc
(`oidc.CheckSignature` with `rp.NewRemoteKeySet`); the `typ`, `iss`, `aud`,
`iat`, `jti`, `sub`/`exp` and subject checks are ours. Do not use
`oidc.Audience` to decode `aud`: it panics on a non-string array element.

## OpenVPN management command size

For `client-pending-auth` URL validation:

- OpenVPN accepts at most 1023 command-body bytes before the terminating LF.
  This is a byte limit. OpenVPN discards this project's CR, so CR does not reduce
  the allowance.
- For `client-pending-auth <CID> <KID> "WEB_AUTH::<URL>" <TIMEOUT>`, the body is
  `35 + digits(CID) + digits(KID) + bytes(URL) + digits(TIMEOUT)` bytes.
- Therefore, the maximum URL size is
  `988 - digits(CID) - digits(KID) - digits(TIMEOUT)` bytes. Assuming a CID of
  at most five digits, a one-digit KID, and timeout `300`, the URL may contain at
  most 979 bytes. Quoting or escaping consumes more.
- Do not confuse a conservative project policy with OpenVPN's actual limit.
- OpenVPN's later TLS `EXTRA` limit is 1013 parsed bytes; the 1023-byte management
  command limit is tighter for this template.

The source evidence is pinned to OpenVPN commit
[`a6537f7549f70f16bb2efd5c0683e0e94a236f0c`](https://github.com/OpenVPN/openvpn/commit/a6537f7549f70f16bb2efd5c0683e0e94a236f0c).
