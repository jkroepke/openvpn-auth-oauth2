# Instructions for AI Agents

The following guidelines apply to all files in this repository.

Follow all development, testing, documentation, and pull request requirements in
[`CONTRIBUTING.md`](CONTRIBUTING.md) before modifying the repository.

## Pull request labels

Applying changelog labels is an AI-agent-only operation. External contributors
must not be instructed to set them.

Before merging, apply at least one changelog label defined in
[`.github/release.yml`](.github/release.yml):

- `💥 breaking-change` for breaking changes
- `✨ enhancement` for new functionality
- `🐞 bug` for fixes
- `🛠️ dependencies` for dependency updates
- `📖 docs` for documentation
- `chore` for internal technical changes excluded from the user-facing changelog

Use `chore` for implementation-only performance improvements, tests, CI, and
maintenance that do not change user-facing behavior. Use `✨ enhancement` only
when a change adds functionality that users can observe or use.

Add `💥 breaking-change` whenever a change is breaking, even if another label
also applies.

## Program overview

`openvpn-auth-oauth2` is written in Go and acts as a management client for an
OpenVPN server. It bridges the OpenVPN [webauth protocol](https://github.com/OpenVPN/openvpn3/blob/master/doc/webauth.md)
with OIDC providers. The executable communicates with the OpenVPN management
interface via a Unix or TCP socket, and it exposes an HTTP listener that handles
browser-based authentication.

The typical authentication flow:

1. A VPN client connects to the OpenVPN server.
2. The server contacts `openvpn-auth-oauth2` using the management interface and
   receives a `WEBAUTH:` URL.
3. The VPN client opens that URL in a browser and logs in against the OIDC
   provider.
4. After a successful login, the token is validated, and the result is sent back to
   the OpenVPN server to complete the connection.

Configuration is usually done through a YAML file or environment variables. The
project's `docs/` directory contains detailed guides such as
[`docs/Configuration.md`](docs/Configuration.md) and
[`docs/Home.md`](docs/Home.md).

## Plugin cgo pointer checks

All tests must be compiled with `GOEXPERIMENT=cgocheck2` so the plugin's Go/C
boundary receives the complete, expensive cgo pointer checks. The `test` target
in `Makefile` and the build-and-test job in `.github/workflows/ci.yaml` set the
experiment at build time.

Do not try to enable the experiment with `//go:debug cgocheck2=1`,
`//go:debug cgocheck=2`, `GODEBUG=cgocheck=2`, or `t.Setenv`. The first is not a
`GODEBUG` setting, while the others cannot enable the build-time instrumentation.

## OpenVPN management command size

When changing the URL-length validation for `client-pending-auth`, distinguish
the project's conservative limit from OpenVPN's actual management-interface
limit. OpenVPN allocates a 1024-byte command accumulator:

```c
man->connection.in = command_line_new(1024);
```

It stores only printable bytes and line feeds. If another stored byte does not
fit, it clears the accumulated command:

```c
if (buf[i] && char_class(buf[i], (CC_PRINT | CC_NEWLINE)))
{
    if (!buf_write_u8(&cl->buf, buf[i]))
    {
        buf_clear(&cl->buf);
    }
}
```

Therefore, a management command may contain at most **1023 bytes before the
terminating LF**. This is a byte limit, not a character limit. This project
writes CRLF in `internal/openvpn/main.go`, but OpenVPN discards CR because the
accepted character classes above include `CC_NEWLINE` and not `CC_CR`; CR does
not reduce the 1023-byte command-body allowance.

For the exact template in `internal/openvpn/client.go`:

```text
client-pending-auth <CID> <KID> "WEB_AUTH::<URL>" <TIMEOUT>
```

the body size is:

```text
35 + digits(CID) + digits(KID) + bytes(URL) + digits(TIMEOUT)
```

Consequently:

```text
maximum URL bytes = 988 - digits(CID) - digits(KID) - digits(TIMEOUT)
```

For example, CID `1`, KID `0`, and timeout `300` permit a URL of at most
**983 bytes**. Quoting or escaping additional characters consumes more bytes.
The existing `len(startURL) >= 245` validation is therefore a conservative
project policy (maximum 244 bytes), not OpenVPN's management command limit.

There is also a later TLS-control-message guard. OpenVPN defines
`PUSH_BUNDLE_SIZE` as 1024 and accepts the parsed `EXTRA` only when
`strlen(extra) + 1 + sizeof("INFO_PRE,") <= 1024`, giving a maximum parsed
`EXTRA` size of 1013 bytes. For this project's command template, the 1023-byte
management command limit is tighter.

Source proof, pinned to OpenVPN commit
[`a6537f7549f70f16bb2efd5c0683e0e94a236f0c`](https://github.com/OpenVPN/openvpn/commit/a6537f7549f70f16bb2efd5c0683e0e94a236f0c):

- [the 1024-byte command accumulator](https://github.com/OpenVPN/openvpn/blob/a6537f7549f70f16bb2efd5c0683e0e94a236f0c/src/openvpn/manage.c#L2743-L2748)
- [input filtering, overflow clearing, and LF detection](https://github.com/OpenVPN/openvpn/blob/a6537f7549f70f16bb2efd5c0683e0e94a236f0c/src/openvpn/manage.c#L4017-L4041)
- [`CC_NEWLINE` and `CC_CR` are separate classes](https://github.com/OpenVPN/openvpn/blob/a6537f7549f70f16bb2efd5c0683e0e94a236f0c/src/openvpn/buffer.h#L918-L947)
- [`PUSH_BUNDLE_SIZE` is 1024](https://github.com/OpenVPN/openvpn/blob/a6537f7549f70f16bb2efd5c0683e0e94a236f0c/src/openvpn/common.h#L84-L89)
- [the `INFO_PRE`/`EXTRA` length check](https://github.com/OpenVPN/openvpn/blob/a6537f7549f70f16bb2efd5c0683e0e94a236f0c/src/openvpn/push.c#L438-L476)
