#!/usr/bin/env bash

docker run -it --rm --privileged --network host -v `pwd`:/host --name futag_libs_ubuntu20 futag_libs_ubuntu20 /bin/bash

