#!/bin/sh

set -e

case $1 in
1 | upgrade | failed-upgrade)
  # RPM: If the first argument is 1, it means the package is being upgraded. https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/#_syntax
  # DEB: If the first argument is upgrade or failed-upgrade, it means the package is being upgraded. https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html#summary-of-ways-maintainer-scripts-are-called
  ;;

*)
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
  ;;
esac
