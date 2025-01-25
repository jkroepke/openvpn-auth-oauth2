FROM ubuntu:24.04

RUN apt update && apt install git build-essential autoconf automake libtool pkg-config libnl-genl-3-dev libcap-ng-dev libssl-dev liblz4-dev liblzo2-dev libpam0g-dev python3-docutils easy-rsa -y

WORKDIR /build/

ARG GIT_BRANCH

#RUN git clone --depth 1 https://github.com/OpenVPN/openvpn.git --branch $GIT_BRANCH .
RUN git clone https://gerrit.openvpn.net/openvpn . && git fetch https://gerrit.openvpn.net/openvpn refs/changes/72/872/4 && git checkout FETCH_HEAD
RUN autoreconf -i -v -f
RUN ./configure
RUN make
RUN make install
