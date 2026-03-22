#!/usr/bin/env bash

docker run -it --rm --privileged --network host -v `pwd`:/host --name futag.alt11 futag.alt11 /bin/bash

