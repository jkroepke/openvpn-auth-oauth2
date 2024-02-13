#!/bin/sh

set -e

if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi

systemd-sysusers
systemd-tmpfiles --create

if [ ! -d /etc/openvpn-auth-oauth2/ ]; then
    systemctl stop openvpn-auth-oauth2 >/dev/null || true

    mkdir /etc/openvpn-auth-oauth2/
    touch /etc/openvpn-auth-oauth2/config.yaml
    chmod 750 /etc/openvpn-auth-oauth2/
    chmod 640 /etc/openvpn-auth-oauth2/config.yaml
    chgrp -R openvpn-auth-oauth2 /etc/openvpn-auth-oauth2/
fi

systemctl --system daemon-reload >/dev/null || true

if systemctl is-active --quiet openvpn-auth-oauth2; then
    systemctl restart openvpn-auth-oauth2 >/dev/null || true
fi