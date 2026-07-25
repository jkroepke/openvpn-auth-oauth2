# Contributing

Contributions are welcome through GitHub pull requests.

## Before You Start

Small fixes and documentation improvements can go directly to a pull request.
Before starting a large feature, breaking change, or substantial refactoring,
[open an issue](https://github.com/jkroepke/openvpn-auth-oauth2/issues/new/choose)
to discuss the proposal with the maintainer.

Read the [developer guide](DEVELOPER.md) for an overview of the project and its
requirements.

## Submit a Pull Request

1. Fork the repository and create a branch for your change.
2. Keep the change focused, and update tests and documentation when needed.
3. Run the required checks:

   ```shell
   make fmt
   make lint
   make test
   ```

4. Sign off each commit with `git commit -s` to certify the
   [Developer Certificate of Origin](https://developercertificate.org/).
5. Open a pull request and explain the change, its reason, and how you tested it.

The pull request title becomes an entry in the changelog. Write it as a concise,
user-facing description of the change.
