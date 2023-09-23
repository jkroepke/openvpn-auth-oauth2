# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2023-09-24

### Added

- deb/rpm packages as binary release
- Added systemd unit file
- Added OAUTH2 provider construct for custom provider handling

### Fixes

- openvpn.bypass is nil

## [1.2.1] - 2023-09-16

### Changes

- Use crypto from zitadel/oidc

### Fixes

- CLI parameter handling

## [1.2.0] - 2023-09-16

### Added

- Option to define custom OIDC discovery, auth and token url
- Option to define custom callback HTML template which is parsed by go template engine

## [1.1.0] - 2023-09-16

### Added

- Option to compare common_name with OIDC IDToken claim
- Option to configure authentication bypass

## [1.0.0] - 2023-09-16

- Using OpenVPN Management Interface instead external binary.

## [0.1.0] - 2023-05-22

- First release

[Unreleased]: https://github.com/jkroepke/openvpn-auth-oauth2/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/jkroepke/openvpn-auth-oauth2/releases/tag/v1.2.0
[1.1.0]: https://github.com/jkroepke/openvpn-auth-oauth2/releases/tag/v1.1.0
[1.0.0]: https://github.com/jkroepke/openvpn-auth-oauth2/releases/tag/v1.0.0
[0.1.0]: https://github.com/jkroepke/openvpn-auth-oauth2/releases/tag/v0.1.0
