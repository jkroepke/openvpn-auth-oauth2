#!/bin/sh

set -e

if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi

systemctl --system daemon-reload >/dev/null || true

if systemctl is-active --quiet openvpn-auth-oauth2; then
    systemctl restart openvpn-auth-oauth2 >/dev/null || true
fi

if [ -d /etc/openvpn-auth-oauth2 ]; then
    chown -R root:openvpn-auth-oauth2 /etc/openvpn-auth-oauth2/ >/dev/null || true
fi
