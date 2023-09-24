#!/bin/sh

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop --now openvpn-auth-oauth2
fi
