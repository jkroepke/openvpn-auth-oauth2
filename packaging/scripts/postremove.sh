#!/bin/sh

set -e

case $1 in
1 | upgrade | failed-upgrade)
  # RPM: If the first argument is 1, it means the package is being upgraded. https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/#_syntax
  # DEB: If the first argument is upgrade or failed-upgrade, it means the package is being upgraded. https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html#summary-of-ways-maintainer-scripts-are-called
  ;;

*)
  if id -g openvpn-auth-oauth2 >/dev/null 2>&1; then
    groupdel openvpn-auth-oauth2 >/dev/null || true
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    exit 0
  fi

  systemctl daemon-reload
  systemctl reset-failed
  ;;
esac
