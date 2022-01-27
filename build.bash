#!/bin/bash

#===-- build.bash -------*- bash script -*-===//
#
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).
#

echo "************************************************"
echo "*      ______  __  __  ______  ___     ______  *"
echo "*     / ____/ / / / / /_  __/ /   |   / ____/  *"
echo "*    / /_    / / / /   / /   / /| |  / / __    *"
echo "*   / __/   / /_/ /   / /   / ___ | / /_/ /    *"
echo "*  /_/      \____/   /_/   /_/  |_| \____/     *"
echo "*                                              *"
echo "*     Fuzzing target Automated Generator       *"
echo "*             a tool of ISP RAS                *"
echo "************************************************"
echo ""


#copy source code to llvm-project
cp -r ../src/futag ../llvm-project/clang-tools-extra/
cp ../src/CMakeLists.txt ../llvm-project/clang-tools-extra/
cp -r ../src/futag-basic/include/futag ../llvm-project/clang/include/
cp -r ../src/futag-basic/lib/futag ../llvm-project/clang/lib/
cp ../src/futag-basic/lib/CMakeLists.txt ../llvm-project/clang/lib/

# create folder for install the instrument
if ! [ -d "../futag" ]
then
    mkdir ../futag
fi
cp ../tools/svace.svres.tmpl ../futag

#configure
cmake -G "Unix Makefiles" ../llvm-project/llvm -DLLVM_BUILD_TESTS=OFF -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../futag -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;compiler-rt"

#make && make install
make -j8 && make -j8 install

if ! [ -d "../futag/tools" ]
then
    mkdir ../futag/tools
fi

cp ../tools/* ../futag/tools/

echo ""
echo "======== End of install script for FUTAG - a fuzzing target automated generator ========"
echo ""