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

futag_src="$(pwd)/../src"
futag_install_folder="$(pwd)/../futag-llvm"
vendors="$(pwd)/../vendors"
custom_llvm="$(pwd)/../custom-llvm/llvm-project"
custom_prepare="$(pwd)/../custom-llvm"

#copy source code to llvm-project
cp -r $vendors/json-3.10.5/single_include/nlohmann $custom_llvm/clang/include/

set -x

clanglibCMakeLists="CMakeLists.txt"
ASTMatchFinderh="ASTMatchFinder.h"
ASTMatchFindercpp="ASTMatchFinder.cpp"
Checkerstd="Checkers.td"
CheckerCMakeLists="CMakeLists.txt"

cp -r $futag_src/clang/include/clang/$ASTMatchFinderh $custom_llvm/clang/include/clang/ASTMatchers/ASTMatchFinder.h
cp -r $futag_src/clang/lib/clang/$ASTMatchFindercpp $custom_llvm/clang/lib/ASTMatchers/ASTMatchFinder.cpp

cp -r $futag_src/clang/include/Futag $custom_llvm/clang/include/
cp $futag_src/clang/lib/$clanglibCMakeLists $custom_llvm/clang/lib/CMakeLists.txt
cp -r $futag_src/clang/lib/Futag $custom_llvm/clang/lib/

# copy clang Checker
cp $futag_src/Checkers/include/$Checkerstd $custom_llvm/clang/include/clang/StaticAnalyzer/Checkers/Checkers.td
cp $futag_src/Checkers/lib/*.cpp $custom_llvm/clang/lib/StaticAnalyzer/Checkers/
cp -r $futag_src/Checkers/lib/$CheckerCMakeLists $custom_llvm/clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt

cmake  -G "Unix Makefiles"  -DLLVM_BUILD_TESTS=OFF  -DLLVM_ENABLE_ZLIB=ON  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$futag_install_folder  -DCMAKE_EXPORT_COMPILE_COMMANDS=1  -DCLANG_INCLUDE_DOCS="OFF"  -DLLVM_BUILD_LLVM_DYLIB="ON"  -DLLVM_ENABLE_BINDINGS="OFF"  -DLLVM_ENABLE_PROJECTS='clang;'  -DLLVM_ENABLE_WARNINGS="OFF"  -DLLVM_INCLUDE_BENCHMARKS="OFF"  -DLLVM_INCLUDE_DOCS="OFF"  -DLLVM_INCLUDE_EXAMPLES="OFF"  -DLLVM_INCLUDE_TESTS="OFF"  -DLLVM_LINK_LLVM_DYLIB="ON"  -DLLVM_TARGETS_TO_BUILD="host" -DLLVM_ENABLE_RUNTIMES="compiler-rt;"  $custom_llvm/llvm

make -j16 && make -j16 install

if [ -d $futag_install_folder/python-package ]
then
    rm -rf $futag_install_folder/python-package
fi
mkdir $futag_install_folder/python-package
cp -r $futag_src/python/futag-package/dist/*.tar.gz $futag_install_folder/python-package
cp -r $futag_src/python/futag-package/requirements.txt $futag_install_folder/python-package
cp -r $futag_src/python/*.py $futag_install_folder/python-package
cp -r $futag_src/svres-tmpl $futag_install_folder/
cp -r ../*.md $futag_install_folder/
cp -r ../LICENSE $futag_install_folder/
cp $custom_prepare/INFO $futag_install_folder/
git rev-parse HEAD >> $futag_install_folder/INFO

cd ../product-tests
XZ_OPT='-T12 -9' tar cJf futag-llvm$version.latest.tar.xz ../futag-llvm

echo ""
echo "======== End of build script for FUTAG - a fuzzing target automated generator ========"
echo ""
