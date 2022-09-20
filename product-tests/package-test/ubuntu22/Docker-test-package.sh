#!/usr/bin/env bash

if [ ! -f ../futag-llvm-package.latest.tar.xz]
then
    echo "-- [Futag]: missing latest package of Futag"
    exit
fi
cp ../futag-llvm-package.latest.tar.xz .

docker build --network=host -t futag_pkg_ubuntu22 -f Docker-test-package.Dockerfile .