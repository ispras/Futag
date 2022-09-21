#!/usr/bin/env bash

docker build --network=host -t futag_libs_ubuntu20 -f Docker-test-libs.Dockerfile .

