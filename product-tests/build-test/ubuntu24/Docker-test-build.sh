#!/usr/bin/env bash

docker build --network=host -t futag_src_ubuntu24 -f Docker-test-build.Dockerfile .

