# This Dockerfile is used by goreleaser (dockers_v2). The binaries are built by goreleaser.
# renovate: docker=gcr.io/distroless/static-debian12
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETPLATFORM

COPY ${TARGETPLATFORM}/openvpn-auth-oauth2 /usr/bin/openvpn-auth-oauth2
COPY LICENSE.txt /usr/share/doc/openvpn-auth-oauth2/LICENSE.txt
COPY 3rdpartylicenses/ /usr/share/doc/openvpn-auth-oauth2/3rdpartylicenses/

EXPOSE 9000

ENTRYPOINT ["/usr/bin/openvpn-auth-oauth2"]
