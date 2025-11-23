FROM golang:1.25 AS builder

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /app/

RUN apt-get update && apt-get install libssl-dev -y --no-install-recommends

COPY . /app/

RUN go build -buildvcs=false -o /plugin/openvpn-auth-oauth2.so -buildmode=c-shared ./lib/openvpn-auth-oauth2/
RUN ls -lah /plugin/openvpn-auth-oauth2.so

# renovate: docker=ubuntu
FROM ubuntu:24.04 AS openvpn

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install git ca-certificates build-essential autoconf automake libtool pkg-config libnl-genl-3-dev libcap-ng-dev libssl-dev liblz4-dev liblzo2-dev libpam0g-dev python3-docutils easy-rsa -y --no-install-recommends

WORKDIR /build/

ARG GIT_BRANCH=master
ARG GIT_REPO=https://github.com/OpenVPN/openvpn.git

ENV EASYRSA=/usr/share/easy-rsa/ \
    EASYRSA_PKI=/etc/openvpn/pki \
    EASYRSA_BATCH=1 \
    EASYRSA_NO_VARS=1 \
    EASYRSA_NO_PASS=1 \
    EASYRSA_ALGO="ed" \
    EASYRSA_CURVE="ed25519" \
    EASYRSA_DN="cn_only"

RUN git init && git remote add origin ${GIT_REPO}
RUN git fetch --depth 1 origin ${GIT_BRANCH} && git checkout FETCH_HEAD
RUN autoreconf -i -v -f
RUN ./configure
RUN make
RUN make install
COPY --from=builder /plugin/openvpn-auth-oauth2.so /plugin/openvpn-auth-oauth2.so
RUN ls -lah /plugin/openvpn-auth-oauth2.so
