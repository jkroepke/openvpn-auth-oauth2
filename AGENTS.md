# Instructions for AI Agents

The following guidelines apply to all files in this repository.

Before you start contributing, read [`DEVELOPER.md`](DEVELOPER.md) for a basic
understanding of how the project is structured and works.

Ensure that that the local go version matches the one specified in
[`go.mod`](go.mod).
Never update the Go version in `go.mod`.

## Programmatic checks

Before committing any changes, always run:

1. `make fmt` – formats all Go code.
2. `make lint` – runs the linter.
3. `make test` – executes the test suite.

If a command fails because of missing dependencies or network restrictions, note this in the PR's Testing section using the provided disclaimer.

## Pull requests

Summarise your changes and cite relevant lines in the repository. Mention the output of the programmatic checks.

## Program overview

`openvpn-auth-oauth2` is written in Go and acts as a management client for an
OpenVPN server. It bridges the OpenVPN [webauth protocol](https://github.com/OpenVPN/openvpn3/blob/master/doc/webauth.md)
with OIDC providers. The executable communicates with the OpenVPN management
interface via a Unix or TCP socket, and it exposes an HTTP listener that handles
browser-based authentication.

The typical authentication flow is:

1. A VPN client connects to the OpenVPN server.
2. The server contacts `openvpn-auth-oauth2` using the management interface and
   receives a `WEBAUTH:` URL.
3. The VPN client opens that URL in a browser and logs in against the OIDC
   provider.
4. After successful login, the token is validated and the result is sent back to
   the OpenVPN server to complete the connection.

Configuration is usually done through a YAML file or environment variables. The
project's `docs/` directory contains detailed guides such as
[`docs/Configuration.md`](docs/Configuration.md) and
[`docs/Home.md`](docs/Home.md).
