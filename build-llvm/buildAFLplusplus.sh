#!/bin/bash

#===-- build.sh -------*- bash script -*-===//
#
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).
#
# This script helps to build  llvm with clang and compiler-rt

echo "************************************************"
echo "*      ______  __  __  ______  ___     ______  *"
echo "*     / ____/ / / / / /_  __/ /   |   / ____/  *"
echo "*    / /_    / / / /   / /   / /| |  / / __    *"
echo "*   / __/   / /_/ /   / /   / ___ | / /_/ /    *"
echo "*  /_/      \____/   /_/   /_/  |_| \____/     *"
echo "*                                              *"
echo "*     Fuzz target Automated Generator       *"
echo "*             a tool of ISP RAS                *"
echo "************************************************"
echo ""

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
echo "Exporting Futag path for AFLplusplus: "$SCRIPTPATH
echo ""
set -x
export PATH="$SCRIPTPATH/bin:$PATH"
export LLVM_CONFIG="$SCRIPTPATH/bin/llvm-config"
export LD_LIBRARY_PATH="$(llvm-config --libdir)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

futag_install_folder="$SCRIPTPATH"

if [ ! -f 4.02c.tar.gz ]; then
    wget https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/4.02c.tar.gz
fi
mv 4.02c.tar.gz $futag_install_folder/

cd $SCRIPTPATH
tar xf 4.02c.tar.gz
# mv AFLplusplus-4.02c $build_folder/
cd AFLplusplus-4.02c
make -j$(($(nproc)/2)) distrib
make -j$(($(nproc)/2)) DESTDIR=$futag_install_folder/AFLplusplus install
