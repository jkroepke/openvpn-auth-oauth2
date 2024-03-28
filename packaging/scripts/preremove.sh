#!/bin/sh

set -e

if command -v apparmor_parser >/dev/null 2>&1 && command -v aa-enabled >/dev/null 2>&1; then
  if aa-enabled --quiet 2>/dev/null; then
    apparmor_parser --remove -T -W /etc/apparmor.d/usr.bin.openvpn-auth-oauth2 || true
  fi
fi

if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi

systemctl stop openvpn-auth-oauth2.service || true
systemctl daemon-reload
systemctl reset-failed
