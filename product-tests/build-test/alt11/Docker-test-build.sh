#!/usr/bin/env bash

# docker build --no-cache --network=host -t futag_src_ubuntu20 -f Docker-test-build.Dockerfile .
docker build --network=host -t futag_alt11 -f alt11.Dockerfile .

