#!/bin/sh

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    if systemctl is-active --quiet openvpn-auth-oauth2; then
        systemctl restart --now --no-block openvpn-auth-oauth2
    fi
fi
