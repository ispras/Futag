#!/usr/bin/env bash

docker build --network=host -t futag_build_ubuntu24 -f ubuntu24.Dockerfile .

