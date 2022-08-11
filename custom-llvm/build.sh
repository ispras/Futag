#!/bin/bash

#===-- build.bash -------*- bash script -*-===//
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
echo "*     Fuzzing target Automated Generator       *"
echo "*             a tool of ISP RAS                *"
echo "************************************************"
echo ""

# cmake  -G "Unix Makefiles" -DLLVM_BUILD_TESTS=OFF -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../futag-llvm-package -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -DLLVM_EXTERNAL_PROJECTS="clang;compiler-rt" -DLLVM_EXTERNAL_CLANG_SOURCE_DIR=../clang -DLLVM_EXTERNAL_COMPILER_RT_SOURCE_DIR=../compiler-rt ../llvm

futag_src="../src"
futag_install_folder="../futag-llvm-package"
vendors="../vendors"
custom_llvm="../custom-llvm"

#copy source code to llvm-project
cp -r $vendors/json-3.10.5/single_include/nlohmann $custom_llvm/clang/include/

cp -r $futag_src/clang/include/Futag $custom_llvm/clang/include/
cp -r $futag_src/clang/lib/* $custom_llvm/clang/lib/

# copy clang Checker
cp -r $futag_src/Checkers/include/Checkers.td $custom_llvm/clang/include/clang/StaticAnalyzer/Checkers/
cp -r $futag_src/Checkers/lib/* $custom_llvm/clang/lib/StaticAnalyzer/Checkers/

cp -r $futag_src/clang/include/clang/ASTMatchFinder.h $custom_llvm/clang/include/clang/ASTMatchers/
cp -r $futag_src/clang/lib/clang/ASTMatchFinder.cpp $custom_llvm/clang/lib/ASTMatchers/


# create futag installation folder
if ! [ -d $futag_install_folder ]
then
    mkdir $futag_install_folder
fi

cmake  -G "Unix Makefiles" -DLLVM_BUILD_TESTS=OFF -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$futag_install_folder -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -DLLVM_EXTERNAL_PROJECTS="clang;compiler-rt" -DLLVM_EXTERNAL_CLANG_SOURCE_DIR=$custom_llvm/clang -DLLVM_EXTERNAL_COMPILER_RT_SOURCE_DIR=$custom_llvm/compiler-rt $custom_llvm/llvm

make -j16 && make -j16 install
mkdir $futag_install_folder/python-package
cp -r $futag_src/python/futag-package/dist/*.tar.gz $futag_install_folder/python-package
cp -r $futag_src/svres-tmpl $futag_install_folder/
cp -r ../README* $futag_install_folder/
cp -r ../LICENSE $futag_install_folder/

echo ""
echo "======== End of install script for FUTAG - a fuzzing target automated generator ========"
echo ""
