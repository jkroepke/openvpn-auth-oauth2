.PHONY: builder-image build clean

ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(shell dirname $(ROOT_DIR))

clean:
	@rm -f *.so

build: clean
	docker run --rm -v $(PROJECT_DIR):/openvpn-auth-oauth2/ -v $(HOME)/go/pkg/mod/cache/:/tmp/go/pkg/mod/cache/ -w /openvpn-auth-oauth2/plugin local/openvpn-plugin-build

builder-image:
	docker build -t local/openvpn-plugin-build .
