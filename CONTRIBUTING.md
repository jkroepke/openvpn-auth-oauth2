# Contributing

Contributions are welcome through GitHub pull requests.

## Before You Start

Small fixes and documentation improvements can go directly to a pull request.
Before starting a large feature, breaking change, or substantial refactoring,
[open an issue](https://github.com/jkroepke/openvpn-auth-oauth2/issues/new/choose)
to discuss the proposal with the maintainer.

Read the [developer guide](DEVELOPER.md) for an overview of the project and its
requirements.

Use the Go version specified in [`go.mod`](go.mod). Never update the Go version
in `go.mod`.

## Required Checks

Before committing a change, run:

```shell
make fmt
make lint
make test
```

If a check cannot run because of missing dependencies or network restrictions,
state that limitation in the pull request's testing notes.

GitHub security alerts are the primary mechanism for dependency CVE tracking.
Do not add or require `govulncheck` as a mandatory local or CI check unless the
maintainer explicitly requests it. It may be used as an optional diagnostic
when investigating a specific Go vulnerability or dependency risk.

## Submit a Pull Request

1. Fork the repository and create a branch for your change.
2. Keep the change focused, and update tests and documentation when needed.
3. Sign off each commit with `git commit -s` to certify the
   [Developer Certificate of Origin](https://developercertificate.org/).
4. Open a pull request and explain the change, its reason, and how you tested
   it. Cite relevant files or lines and include the required check results.

Pull request titles are published in user-facing release notes. Write each title
as a concise description of the user-visible change and start it with `feat:`,
`fix:`, `docs:`, or `chore:` as required by CI. Use the `!` form, such as
`feat!:`, for a breaking change.

## Documentation

Documentation must follow the
[textlint terminology rules](https://github.com/sapegin/textlint-rule-terminology/blob/master/terms.jsonc).
