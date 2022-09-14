#!/usr/bin/env bash

docker run -it --rm --privileged --network host -v `pwd`:/host --name futag_src_ubuntu22 futag_src_ubuntu22 /bin/bash

