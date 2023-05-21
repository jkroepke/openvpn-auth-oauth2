# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0]
### Changed

- Changed source code language from Python to Go
- Not longer using OpenVPN management interface. openvpn-auth-azure-ad is not longer a daemon.

### Removed

- Resource Owner Password Credentials grant flow

## [2.1.0]

### Added
- Support for WebAuth SSO (not supported by Tunnelblick)

### Changed

- Fix ModuleNotFoundError: No module named 'configargparse'

## [2.0.1]

### Added

- Automatic docker build in CI

## [2.0.0]

### Added

- Support management-hold
- Added `--verify-openvpn-client-id-token-claim`
- Better handling in reconnection scenarios
- Better logging

### Changed

- Change `--verify-common-name` to `--verify-openvpn-client`
- Refactor project to PEP-517 standard

### Removed

## [1.2.0] - 2020-09-20

### Added

- Add validation between client certificate and id_token

### Changed

### Removed

## [1.1.3] - 2020-08-17

### Changed

- Fixed auth_token behavior

## [1.1.2] - 2020-08-17

### Added

- Added reconnect mechanism

## [1.1.1] - 2020-08-16

### Added

- Update documentation

## [1.1.0] - 2020-08-16

### Added

- Multi-Thread support
- Terminate program if connection to OpenVPN closed.

## [1.0.1] - 2020-08-16

- Fixed release automation

## [1.0.0] - 2020-08-16

- First official release

## [0.0.5] - 2020-08-16

- fixed version

## [0.0.4] - 2020-08-16

- move package into subdir

## [0.0.3] - 2020-08-16

- fixed pip release

## [0.0.2] - 2020-08-16

- add auth-token support

## [0.0.1] - 2020-08-14

- First release

[Unreleased]: https://github.com/jkroepke/openvpn-auth-azure-ad/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v3.0.0
[2.1.0]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v2.1.0
[2.0.3]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v2.0.3
[2.0.1]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v2.0.1
[2.0.0]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v2.0.0
[1.2.0]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v1.2.0
[1.1.3]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v1.1.3
[1.1.2]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v1.1.2
[1.1.1]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v1.1.1
[1.1.0]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v1.1.0
[1.0.1]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v1.0.1
[1.0.0]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v1.0.0
[0.0.5]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v0.0.5
[0.0.4]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v0.0.4
[0.0.3]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v0.0.3
[0.0.2]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v0.0.2
[0.0.1]: https://github.com/jkroepke/openvpn-auth-azure-ad/releases/tag/v0.0.1
