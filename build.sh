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
cp -r ../vendors/json-3.10.5/single_include/nlohmann ../llvm-project/clang/include/

# copy clang libtooling
# cp -r ../src/clang-tools-extra/* ../llvm-project/clang-tools-extra/

cp -r ../src/clang/include/Futag ../llvm-project/clang/include/
cp -r ../src/clang/lib/* ../llvm-project/clang/lib/

# copy clang Checker
cp -r ../src/Checkers/include/Checkers.td ../llvm-project/clang/include/clang/StaticAnalyzer/Checkers/
cp -r ../src/Checkers/lib/* ../llvm-project/clang/lib/StaticAnalyzer/Checkers/

cp -r ../src/clang/include/clang/ASTMatchFinder.h ../llvm-project/clang/include/clang/ASTMatchers/
cp -r ../src/clang/lib/clang/ASTMatchFinder.cpp ../llvm-project/clang/lib/ASTMatchers/


# create futag installation folder
if ! [ -d "../../futag-package" ]
then
    mkdir ../../futag-package
fi
# cp ../tools/svace.svres.tmpl ../futag

#configure
cmake -G "Unix Makefiles" ../llvm-project/llvm -DLLVM_BUILD_TESTS=OFF -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../../futag-package -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;compiler-rt"

#make && make install
make -j16 && make -j16 install

if ! [ -d "../../futag-package/tools" ]
then
    mkdir ../../futag-package/tools
fi

cp -r ../src/python ../../futag-package/

echo ""
echo "======== End of install script for FUTAG - a fuzzing target automated generator ========"
echo ""
