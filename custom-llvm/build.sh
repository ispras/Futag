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

futag_src="$(pwd)/../src"
futag_install_folder="$(pwd)/../futag-llvm"
vendors="$(pwd)/../vendors"
custom_llvm="$(pwd)/../custom-llvm/llvm-project"
custom_prepare="$(pwd)/../custom-llvm"

#copy source code to llvm-project
cp -r $vendors/json-3.10.5/single_include/nlohmann $custom_llvm/clang/include/

set -x

llvmVersion=$(head -n 1 $custom_prepare/INFO)
version=""

if [ $llvmVersion == "LLVM=18.1.8" ]; then
    version="18"
fi

if [ $llvmVersion == "LLVM=14.0.6" ]; then
    version="14"
fi

clanglibCMakeLists="CMakeLists$version.txt"
ASTMatchFinderh="ASTMatchFinder$version.h"
ASTMatchFindercpp="ASTMatchFinder$version.cpp"
Checkerstd="Checkers$version.td"
CheckerCMakeLists="CMakeLists$version.txt"
FutagAnalyzer="FutagAnalyzer$version.cpp"
FutagConsumerAnalyzer="FutagConsumerAnalyzer$version.cpp"

cp -r $futag_src/clang/include/clang/$ASTMatchFinderh $custom_llvm/clang/include/clang/ASTMatchers/ASTMatchFinder.h
cp -r $futag_src/clang/lib/clang/$ASTMatchFindercpp $custom_llvm/clang/lib/ASTMatchers/ASTMatchFinder.cpp

cp -r $futag_src/clang/include/Futag $custom_llvm/clang/include/
cp $futag_src/clang/lib/$clanglibCMakeLists $custom_llvm/clang/lib/CMakeLists.txt
cp -r $futag_src/clang/lib/Futag $custom_llvm/clang/lib/

# copy clang Checker
cp $futag_src/Checkers/include/$Checkerstd $custom_llvm/clang/include/clang/StaticAnalyzer/Checkers/Checkers.td
cp $futag_src/Checkers/lib/$FutagConsumerAnalyzer $custom_llvm/clang/lib/StaticAnalyzer/Checkers/FutagConsumerAnalyzer.cpp
cp $futag_src/Checkers/lib/$FutagAnalyzer $custom_llvm/clang/lib/StaticAnalyzer/Checkers/FutagAnalyzer.cpp
cp -r $futag_src/Checkers/lib/$CheckerCMakeLists $custom_llvm/clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt

if [ $llvmVersion == "LLVM=19.1.7" ]; then
    cmake  -G "Unix Makefiles"  -DCMAKE_POLICY_WARNING_CMP=FALSE -DLLVM_BUILD_TESTS=OFF -DLLVM_ENABLE_ZLIB=ON  -DCMAKE_BUILD_TYPE=Release  -DLLVM_BINUTILS_INCDIR=/usr/include/  -DCMAKE_INSTALL_PREFIX=$futag_install_folder  -DCMAKE_EXPORT_COMPILE_COMMANDS=1  -DCLANG_INCLUDE_DOCS="OFF"  -DLLVM_BUILD_LLVM_DYLIB="ON"  -DLLVM_ENABLE_BINDINGS="OFF"  -DLLVM_ENABLE_PROJECTS='clang;lld;compiler-rt'  -DLLVM_ENABLE_WARNINGS="OFF"  -DLLVM_INCLUDE_BENCHMARKS="OFF"  -DLLVM_INCLUDE_DOCS="OFF"  -DLLVM_INCLUDE_EXAMPLES="OFF"  -DLLVM_INCLUDE_TESTS="OFF"  -DLLVM_LINK_LLVM_DYLIB="ON"  -DLLVM_TARGETS_TO_BUILD="host" $custom_llvm/llvm

fi
if [ $llvmVersion == "LLVM=18.1.8" ]; then
    cmake  -G "Unix Makefiles"  -DLLVM_BUILD_TESTS=OFF -DLLVM_ENABLE_ZLIB=ON  -DCMAKE_BUILD_TYPE=Release  -DLLVM_BINUTILS_INCDIR=/usr/include/  -DCMAKE_INSTALL_PREFIX=$futag_install_folder  -DCMAKE_EXPORT_COMPILE_COMMANDS=1  -DCLANG_INCLUDE_DOCS="OFF"  -DLLVM_BUILD_LLVM_DYLIB="ON"  -DLLVM_ENABLE_BINDINGS="OFF"  -DLLVM_ENABLE_PROJECTS='clang;lld;compiler-rt' -DLLVM_ENABLE_WARNINGS="OFF"  -DLLVM_INCLUDE_BENCHMARKS="OFF"  -DLLVM_INCLUDE_DOCS="OFF"  -DLLVM_INCLUDE_EXAMPLES="OFF"  -DLLVM_INCLUDE_TESTS="OFF"  -DLLVM_LINK_LLVM_DYLIB="ON"  -DLLVM_TARGETS_TO_BUILD="host" $custom_llvm/llvm

fi

if [ $llvmVersion == "LLVM=14.0.6" ]; then
    cmake  -G "Unix Makefiles" -DLLVM_BUILD_TESTS=OFF  -DLLVM_ENABLE_ZLIB=ON  -DCMAKE_BUILD_TYPE=Release  -DLLVM_BINUTILS_INCDIR=/usr/include/  -DCMAKE_INSTALL_PREFIX=$futag_install_folder  -DCMAKE_EXPORT_COMPILE_COMMANDS=1  -DCLANG_INCLUDE_DOCS="OFF"  -DLLVM_BUILD_LLVM_DYLIB="ON"  -DLLVM_ENABLE_BINDINGS="OFF"  -DLLVM_ENABLE_PROJECTS='clang;lld'  -DLLVM_ENABLE_WARNINGS="OFF"  -DLLVM_INCLUDE_BENCHMARKS="OFF"  -DLLVM_INCLUDE_DOCS="OFF"  -DLLVM_INCLUDE_EXAMPLES="OFF"  -DLLVM_INCLUDE_TESTS="OFF"  -DLLVM_LINK_LLVM_DYLIB="ON"  -DLLVM_TARGETS_TO_BUILD="host" -DLLVM_ENABLE_RUNTIMES="compiler-rt"  $custom_llvm/llvm

fi

make -j$(($(nproc)/2)) && make -j$(($(nproc)/2)) install

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

cp $custom_prepare/buildAFLplusplus.sh $futag_install_folder/

cd ../product-tests

XZ_OPT='-T'$(($(nproc)/2))' -9' tar cJf futag-llvm$version.latest.tar.xz ../futag-llvm

echo ""
echo "======== End of build script for FUTAG - a Fuzz target automated generator ========"
echo ""
