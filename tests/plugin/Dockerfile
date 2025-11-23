FROM golang:1.25 AS builder

ARG DEBIAN_FRONTEND=noninteractive

ENV EASYRSA=/usr/share/easy-rsa/ \
    EASYRSA_PKI=/etc/openvpn/pki \
    EASYRSA_BATCH=1 \
    EASYRSA_NO_VARS=1 \
    EASYRSA_NO_PASS=1 \
    EASYRSA_ALGO="ed" \
    EASYRSA_CURVE="ed25519" \
    EASYRSA_DN="cn_only"

WORKDIR /app/

RUN apt-get update && apt-get install libssl-dev openvpn easy-rsa -y --no-install-recommends

COPY . /app/

RUN go build -buildvcs=false -o /plugin/openvpn-auth-oauth2.so -buildmode=c-shared ./lib/openvpn-auth-oauth2/
RUN ls -lah /plugin/openvpn-auth-oauth2.so
