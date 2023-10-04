FROM ubuntu:22.04

ARG GO_VERSION=1.21.1
ARG GO_ARCH=amd64

RUN apt update && apt install curl ca-certificates libssl-dev build-essential openvpn -y
RUN curl -sSfL https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz | tar xzf - -C /usr/local/  \
    && ln -s /usr/local/go/bin/go /usr/local/bin/go  \
    && go version

CMD go build -o openvpn-auth-oauth2.so -buildmode=c-shared .
