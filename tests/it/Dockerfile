# renovate: docker=ubuntu
FROM ubuntu:26.04 AS openvpn

ENV EASYRSA=/usr/share/easy-rsa/ \
    EASYRSA_PKI=/etc/openvpn/pki \
    EASYRSA_BATCH=1 \
    EASYRSA_NO_VARS=1 \
    EASYRSA_NO_PASS=1 \
    EASYRSA_ALGO="ed" \
    EASYRSA_CURVE="ed25519" \
    EASYRSA_DN="cn_only"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update  \
    && apt-get install socat git ca-certificates build-essential autoconf automake libtool pkg-config libnl-genl-3-dev libcap-ng-dev libssl-dev liblz4-dev liblzo2-dev libpam0g-dev python3-docutils easy-rsa openvpn -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
