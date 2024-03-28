#!/bin/sh

set -e

if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi

if command -v apparmor_parser >/dev/null 2>&1 && command -v aa-enabled >/dev/null 2>&1; then
  if aa-enabled --quiet 2>/dev/null; then
    apparmor_parser --replace -T -W /etc/apparmor.d/usr.bin.openvpn-auth-oauth2 || true
  fi
fi

systemctl --system daemon-reload >/dev/null || true

if systemctl is-active --quiet openvpn-auth-oauth2; then
    systemctl restart openvpn-auth-oauth2 >/dev/null || true
fi

systemd-sysusers /usr/lib/sysusers.d/openvpn-auth-oauth2.conf >/dev/null || true

if [ -d /etc/openvpn-auth-oauth2 ]; then
    chown -R root:openvpn-auth-oauth2 /etc/openvpn-auth-oauth2/ >/dev/null || true
fi
