#!/bin/bash

XZ_OPT=-9 tar cJf futag-llvm-package.tar.xz ../futag-llvm-package
mv futag-llvm-package.tar.xz package-test/
