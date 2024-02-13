#!/bin/sh

set -e

if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi

systemctl daemon-reload
systemctl reset-failed