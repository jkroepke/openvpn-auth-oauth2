# Installation

## Linux Packages

DEB/RPM packages are available at https://github.com/jkroepke/openvpn-auth-oauth2/releases/latest

1. Download package
2. Install it with command below:

For Ubuntu:

```bash
sudo dpkg -i <package_file>.deb
```

For Centos:

```bash
sudo yum localinstall <package_file>.rpm
```

## Manual

Go to https://github.com/jkroepke/openvpn-auth-oauth2/releases/latest and download the binary to the openvpn server.

To build project you need Golang and Make installed.

`make build`

Move `openvpn-auth-oauth2` binary to `/usr/bin/`.
