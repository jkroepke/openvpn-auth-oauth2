FROM ubuntu:22.04

ARG GIT_BRANCH=release/2.6

RUN apt update && apt install git build-essential autoconf automake libtool pkg-config libnl-genl-3-dev libcap-ng-dev libssl-dev liblz4-dev liblzo2-dev libpam0g-dev python3-docutils easy-rsa -y

WORKDIR /build/

RUN git clone --depth 1 https://github.com/OpenVPN/openvpn.git --branch $GIT_BRANCH --single-branch .
RUN autoreconf -i -v -f
RUN ./configure
RUN make
RUN make install
