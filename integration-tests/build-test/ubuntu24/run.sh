#!/usr/bin/env bash

docker run -it --rm --privileged --network host -v `pwd`:/host --name futag_build_ubuntu24 futag_build_ubuntu24 /bin/bash

