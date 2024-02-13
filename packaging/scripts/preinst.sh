#!/bin/sh

if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi
