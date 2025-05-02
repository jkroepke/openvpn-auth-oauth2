# Client specific configuration

## Introduction

This document describes the client-specific configuration options of openvpn-auth-oauth2.
It mimics the client-config-dir capability of OpenVPN.
But instead the client username, a token claim is used as config identifier.

## Configuration

The feature must be enabled with `--openvpn.client-config.enabled`.
`--openvpn.client-config.path` points to a directory where the client-specific configuration files are stored.

openvpn-auth-oauth2 looks for a file
named after the token claim or common name with `.conf` suffix in the client config directory.
