#!/usr/bin/env bash

docker build --network=host -t futag_src_ubuntu22 -f Docker-test-build.Dockerfile .

