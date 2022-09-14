#!/usr/bin/env bash

docker build --network=host -t futag_pkg_ubuntu22 -f Docker-test-package.Dockerfile .

