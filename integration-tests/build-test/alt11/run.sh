#!/usr/bin/env bash

docker run -it --rm --privileged --network host -v `pwd`:/host --name futag_alt11 futag_alt11 /bin/bash

