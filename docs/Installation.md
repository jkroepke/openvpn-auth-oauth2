# Installation Guide

This document provides detailed instructions on how to install `openvpn-auth-oauth2`.

## Installing via Linux Packages

We provide DEB/RPM packages for Linux distributions. You can download the latest package from our [releases page](https://github.com/jkroepke/openvpn-auth-oauth2/releases/latest).

### For Debian based distributions:

openvpn-auth-oauth2 provides a APT repository for Debian based distributions. You can add the repository to your system and install the package using the following commands:

```bash
curl -L https://raw.githubusercontent.com/jkroepke/openvpn-auth-oauth2/refs/heads/main/packaging/apt/openvpn-auth-oauth2.sources | sudo tee /etc/apt/sources.list.d/openvpn-auth-oauth2.sources
sudo apt update
sudo apt install openvpn-auth-oauth2
```

Note: The apt repository exclusively locates to the latest release.
To pin a specific version, use `https://github.com/jkroepke/openvpn-auth-oauth2/releases/download/vX.Y.Z` as URIs in the sources file.

**Alternatively, you can install the DEB package manually:**

1. Download the DEB package from the releases page.
2. Open a terminal.
3. Navigate to the directory where you downloaded the package.
4. Install the package using the following command:

```bash
sudo dpkg -i <package_file>.deb
```

Replace `<package_file>` with the name of the downloaded file.

### For RedHat based distributions:

1. Download the DEB package from the releases page.
2. Open a terminal.
3. Navigate to the directory where you downloaded the package.
4. Install the package using the following command:


```bash
sudo yum localinstall <package_file>.rpm
```

Replace `<package_file>` with the name of the downloaded file.

## Manual Installation

If you prefer to build the binary yourself, follow these steps:
1. Ensure you have [golang](https://go.dev/doc/install) and Make installed on your system.
2. Download the source code from our [releases page](https://github.com/jkroepke/openvpn-auth-oauth2/releases/latest).
3. Open a terminal.
4. Navigate to the directory where you downloaded the source code.
5. Build the binary using the following command:
    ```bash
    make build
    ```
    This will create a binary file named openvpn-auth-oauth2.
6. Move the `openvpn-auth-oauth2` binary to /usr/bin/ using the following command:
    ```bash
    sudo mv openvpn-auth-oauth2 /usr/bin/
    ```
