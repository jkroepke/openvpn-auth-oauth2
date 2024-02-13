#!/bin/sh

if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi

echo 'g openvpn-auth-oauth2 - -' | systemd-sysusers --replace=/usr/lib/sysusers.d/openvpn-auth-oauth2.conf -  >/dev/null 2>&1
