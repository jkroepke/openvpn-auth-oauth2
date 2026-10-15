# Metrics

`openvpn-auth-oauth2` can expose operational metrics in the
[Prometheus text format](https://prometheus.io/docs/instrumenting/exposition_formats/).
The endpoint is served on the debug listener and is disabled by default.

## Enable the endpoint

```yaml
debug:
  metrics: true
  listen: "127.0.0.1:9001"
```

Or use `--debug.metrics` or `OPENVPN_AUTH_OAUTH2_DEBUG_METRICS=true`. The
metrics are then available at `http://127.0.0.1:9001/metrics`.

The debug listener only serves the profiling endpoints when `debug.pprof` is
enabled as well. Enabling `debug.metrics` alone does not expose profiling data.

The endpoint has no authentication. Keep `debug.listen` on a loopback or
otherwise protected address, and let Prometheus or a local agent scrape it.

## Available metrics

All metrics use the `openvpn_auth_oauth2_` prefix.

| Metric                                                      | Type      | Labels                            | Description                                                                                                                      |
|-------------------------------------------------------------|-----------|-----------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `openvpn_auth_oauth2_build_info`                            | gauge     | `version`, `commit`, `goversion`  | Always `1`. Identifies the running build.                                                                                        |
| `openvpn_auth_oauth2_openvpn_client_accepted_total`         | counter   |                                   | Clients accepted on the OpenVPN management interface, including bypassed and silently re-authenticated clients.                 |
| `openvpn_auth_oauth2_openvpn_client_denied_total`           | counter   | `reason`                          | Clients denied on the OpenVPN management interface.                                                                              |
| `openvpn_auth_oauth2_oauth2_silent_reauth_total`            | counter   | `result`                          | Silent re-authentication attempts with a stored refresh token.                                                                   |
| `openvpn_auth_oauth2_oauth2_code_exchange_duration_seconds` | histogram |                                   | Time from the OAuth2 callback request until tokens, and user info if `oauth2.user-info` is enabled, have been received and validated. |
| `openvpn_auth_oauth2_openvpn_command_duration_seconds`      | histogram | `command`                         | Round-trip time of answered commands sent to the OpenVPN management interface, for example `client-auth` or `client-deny`. Timed-out or canceled commands aren't recorded. |
| `openvpn_auth_oauth2_openvpn_client_queue_length`           | gauge     |                                   | OpenVPN client events waiting for a worker.                                                                                      |
| `openvpn_auth_oauth2_ssf_events_total`                      | counter   | `outcome`                         | [Shared Signals](Shared%20Signals) security events received.                                                                     |
| `openvpn_auth_oauth2_ssf_sessions_revoked_total`            | counter   | `scope`                           | OpenVPN sessions revoked by a Shared Signals event. `scope` is `session` or `user`.                                             |
| `openvpn_auth_oauth2_ssf_poll_errors_total`                 | counter   |                                   | Failed Shared Signals poll requests.                                                                                             |
| `openvpn_auth_oauth2_ssf_last_successful_poll_timestamp_seconds` | gauge |                                   | Unix time of the last successful Shared Signals poll, or `0` if none succeeded yet.                                             |

### Deny reasons

The `reason` label is the reason sent to OpenVPN with `client-deny`, converted
to lowercase with underscores, for example `client_rejected`,
`invalid_client_config`, or `internal_error`. The set of reasons is fixed. Hyphens also become
underscores, so `client re-authentication not enabled` is reported as
`client_re_authentication_not_enabled`.

### Silent re-authentication results

| Result     | Meaning                                                                                                 |
|------------|---------------------------------------------------------------------------------------------------------|
| `success`  | The stored token was valid and the client was re-authenticated without a browser login.                 |
| `fallback` | No usable stored token was found. The client continues with an interactive browser login.               |
| `error`    | Loading or refreshing the stored token failed, or the refreshed identity failed validation. The client continues with an interactive browser login. |

Commands that external management clients send through the
[management interface pass-through](Management%20Interface%20pass-through)
aren't measured.

### Shared Signals event outcomes

| Outcome    | Meaning                                                                                                   |
|------------|-----------------------------------------------------------------------------------------------------------|
| `revoked`  | A `session-revoked` event matched and ended at least one OpenVPN session.                                 |
| `no_match` | A `session-revoked` event matched no OpenVPN session, or it names a whole user while `ssf.user-level-revocation` is disabled. |
| `ignored`  | The event type or subject isn't supported. The event was acknowledged.                                    |
| `invalid`  | The event failed verification and was reported to the transmitter as an error.                            |
| `replay`   | The event was already processed.                                                                          |
| `error`    | Ending a matched session failed, or the signing keys couldn't be fetched to verify the event. The event wasn't acknowledged, so the transmitter delivers it again. |

## Reset behavior

Metrics are kept in memory. A restart or a configuration reload with `SIGUSR1`
resets all counters. Prometheus functions such as `rate()` and `increase()`
handle these resets.

## Example queries

Share of denied logins over the last 15 minutes:

```promql
sum(rate(openvpn_auth_oauth2_openvpn_client_denied_total[15m]))
/
(
  sum(rate(openvpn_auth_oauth2_openvpn_client_denied_total[15m]))
  + sum(rate(openvpn_auth_oauth2_openvpn_client_accepted_total[15m]))
)
```

95th percentile of the OAuth2 code exchange duration:

```promql
histogram_quantile(0.95, sum by (le) (rate(openvpn_auth_oauth2_oauth2_code_exchange_duration_seconds_bucket[5m])))
```
