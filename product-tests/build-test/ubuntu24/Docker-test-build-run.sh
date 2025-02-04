#!/usr/bin/env bash

docker run -it --rm --privileged --network host -v `pwd`:/host --name futag_src_ubuntu24 futag_src_ubuntu24 /bin/bash

