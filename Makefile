#
# Copyright (c) 2019 IoTech
#
# SPDX-License-Identifier: Apache-2.0
#

.PHONY: build clean docker

USER=$(shell id -u)
GROUP=$(shell id -g)

build:
	./scripts/build.sh

clean:
	@rm -rf deps build src/c/iot include/iot release

docker:
	docker build -t device-sdk-c-builder -f scripts/Dockerfile.alpine-3.9 .
	docker run --rm -e UID=$(USER) -e GID=$(GROUP) -v $(PWD)/results:/edgex-c-sdk/results device-sdk-c-builder