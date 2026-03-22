#!/bin/bash

XZ_OPT='-T8 -9' tar cJf futag-llvm.latest.tar.xz ../futag-llvm
mv futag-llvm.latest.tar.xz package-test/
