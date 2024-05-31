FROM ubuntu:24.04

ENV HOME=/tmp

ARG GO_VERSION=1.21.1
ARG GO_ARCH=amd64

RUN dpkg --add-architecture arm64  \
    && apt update  \
    && apt install --no-install-recommends curl ca-certificates libssl-dev build-essential openvpn libssl-dev:arm64 crossbuild-essential-arm64 -y

RUN curl --proto "=https" --tlsv1.2 -sSf -L https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz | tar xzf - -C /usr/local/  \
    && ln -s /usr/local/go/bin/go /usr/local/bin/go  \
    && go version

USER 1001

CMD go build -o openvpn-auth-oauth2.so -buildmode=c-shared .
