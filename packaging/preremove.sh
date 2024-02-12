#!/bin/sh

set -e

if [ -x "$(command -v deluser)" ]; then
     deluser --quiet --system openvpn-auth-oauth2 > /dev/null || true
  else
     echo >&2 "not removing openvpn-auth-oauth2 system account because deluser command was not found"
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable -q --now openvpn-auth-oauth2 > /dev/null 2>&1 || true
fi
