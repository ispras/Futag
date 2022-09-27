#!/bin/bash

XZ_OPT='-T8 -9' tar cJf futag-llvm-package.latest.tar.xz ../futag-llvm-package
mv futag-llvm-package.latest.tar.xz package-test/
