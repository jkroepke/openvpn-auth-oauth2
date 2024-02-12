#!/bin/sh

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable -q --now openvpn-auth-oauth2 > /dev/null 2>&1 || true
fi
