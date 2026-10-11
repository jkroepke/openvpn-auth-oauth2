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
