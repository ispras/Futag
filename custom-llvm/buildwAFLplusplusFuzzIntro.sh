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
echo "*     Fuzz target Automated Generator       *"
echo "*             a tool of ISP RAS                *"
echo "************************************************"
echo ""

futag_src="$(pwd)/../src"
futag_install_folder="$(pwd)/../futag-llvm"
vendors="$(pwd)/../vendors"
custom_llvm="$(pwd)/../custom-llvm/llvm-project"
custom_prepare="$(pwd)/../custom-llvm"
build_folder="$(pwd)"

fuzz_introspector=$futag_install_folder/fuzz-introspector-1.0.0
cd $custom_llvm
$fuzz_introspector/sed_cmds.sh
cp -rf $fuzz_introspector/frontends/llvm/include/llvm/Transforms/FuzzIntrospector/ $custom_llvm/llvm/include/llvm/Transforms/FuzzIntrospector
cp -rf $fuzz_introspector/frontends/llvm/lib/Transforms/FuzzIntrospector $custom_llvm/llvm/lib/Transforms/FuzzIntrospector

cd $build_folder

#copy source code to llvm-project
cp -r $vendors/json-3.10.5/single_include/nlohmann $custom_llvm/clang/include/

set -x

llvmVersion=$(head -n 1 $custom_prepare/INFO)
version=""

if [ $llvmVersion == "LLVM=13.0.1" ]; then
    version="13"
fi
if [ $llvmVersion == "LLVM=12.0.1" ]; then
    version="12"
fi

clanglibCMakeLists="CMakeLists$version.txt"
ASTMatchFinderh="ASTMatchFinder$version.h"
ASTMatchFindercpp="ASTMatchFinder$version.cpp"
Checkerstd="Checkers$version.td"
CheckerCMakeLists="CMakeLists$version.txt"

cp -r $futag_src/clang/include/clang/$ASTMatchFinderh $custom_llvm/clang/include/clang/ASTMatchers/ASTMatchFinder.h
cp -r $futag_src/clang/lib/clang/$ASTMatchFindercpp $custom_llvm/clang/lib/ASTMatchers/ASTMatchFinder.cpp

cp -r $futag_src/clang/include/Futag $custom_llvm/clang/include/
cp $futag_src/clang/lib/$clanglibCMakeLists $custom_llvm/clang/lib/CMakeLists.txt
cp -r $futag_src/clang/lib/Futag $custom_llvm/clang/lib/

# copy clang Checker
cp $futag_src/Checkers/include/$Checkerstd $custom_llvm/clang/include/clang/StaticAnalyzer/Checkers/Checkers.td
cp $futag_src/Checkers/lib/FutagAnalyzer.cpp $custom_llvm/clang/lib/StaticAnalyzer/Checkers/
cp $futag_src/Checkers/lib/FutagContextConsumer.cpp $custom_llvm/clang/lib/StaticAnalyzer/Checkers/
cp -r $futag_src/Checkers/lib/$CheckerCMakeLists $custom_llvm/clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt

# # copy clang Plugin
# cp -r $futag_src/Plugins/* $custom_llvm/clang/

# # copy Futag Slicer
# cp -r $futag_src/Slicer/include/* $custom_llvm/clang/include/
# cp -r $futag_src/Slicer/FutagSlicer $custom_llvm/clang-tools-extra/
# cp $futag_src/Slicer/CMakeLists.txt $custom_llvm/clang-tools-extra/

if [ $llvmVersion == "LLVM=14.0.6" ]; then
    cmake  -G "Unix Makefiles"  -DLLVM_BUILD_TESTS=OFF  -DLLVM_ENABLE_ZLIB=OFF  -DCMAKE_BUILD_TYPE=Release  -DLLVM_BINUTILS_INCDIR=/usr/include/  -DCMAKE_INSTALL_PREFIX=$futag_install_folder  -DCMAKE_EXPORT_COMPILE_COMMANDS=1  -DCLANG_INCLUDE_DOCS="OFF"  -DLLVM_BUILD_LLVM_DYLIB="ON"  -DLLVM_ENABLE_BINDINGS="OFF"  -DLLVM_ENABLE_PROJECTS='clang;'  -DLLVM_ENABLE_WARNINGS="OFF"  -DLLVM_INCLUDE_BENCHMARKS="OFF"  -DLLVM_INCLUDE_DOCS="OFF"  -DLLVM_INCLUDE_EXAMPLES="OFF"  -DLLVM_INCLUDE_TESTS="OFF"  -DLLVM_LINK_LLVM_DYLIB="ON"  -DLLVM_TARGETS_TO_BUILD="host" -DLLVM_ENABLE_RUNTIMES="compiler-rt;lld"  $custom_llvm/llvm

fi
if [ $llvmVersion == "LLVM=13.0.1" ]; then
    cmake  -G "Unix Makefiles"  -DLLVM_BUILD_TESTS=OFF  -DLLVM_ENABLE_ZLIB=OFF  -DCMAKE_BUILD_TYPE=Release  -DLLVM_BINUTILS_INCDIR=/usr/include/  -DCMAKE_INSTALL_PREFIX=$futag_install_folder  -DCMAKE_EXPORT_COMPILE_COMMANDS=1  -DCLANG_INCLUDE_DOCS="OFF"  -DLLVM_BUILD_LLVM_DYLIB="ON"  -DLLVM_ENABLE_BINDINGS="OFF"  -DLLVM_ENABLE_PROJECTS='clang;compiler-rt;lld'  -DLLVM_ENABLE_WARNINGS="OFF"  -DLLVM_INCLUDE_BENCHMARKS="OFF"  -DLLVM_INCLUDE_DOCS="OFF"  -DLLVM_INCLUDE_EXAMPLES="OFF"  -DLLVM_INCLUDE_TESTS="OFF"  -DLLVM_LINK_LLVM_DYLIB="ON"  -DLLVM_TARGETS_TO_BUILD="host"  $custom_llvm/llvm

fi
if [ $llvmVersion == "LLVM=12.0.1" ]; then
    cmake  -G "Unix Makefiles"  -DLLVM_BUILD_TESTS=OFF  -DLLVM_ENABLE_ZLIB=OFF  -DCMAKE_BUILD_TYPE=Release  -DLLVM_BINUTILS_INCDIR=/usr/include/  -DCMAKE_INSTALL_PREFIX=$futag_install_folder  -DCMAKE_EXPORT_COMPILE_COMMANDS=1  -DCLANG_INCLUDE_DOCS="OFF"  -DLLVM_BUILD_LLVM_DYLIB="ON"  -DLLVM_ENABLE_BINDINGS="OFF"  -DLLVM_ENABLE_PROJECTS='clang;compiler-rt;'  -DLLVM_ENABLE_WARNINGS="OFF"  -DLLVM_INCLUDE_BENCHMARKS="OFF"  -DLLVM_INCLUDE_DOCS="OFF"  -DLLVM_INCLUDE_EXAMPLES="OFF"  -DLLVM_INCLUDE_TESTS="OFF"  -DLLVM_LINK_LLVM_DYLIB="ON"  -DLLVM_TARGETS_TO_BUILD="host" $custom_llvm/llvm

fi

make -j8 && make -j8 install
cp lib/LLVMgold.so $futag_install_folder/lib/
if [ ! -d $futag_install_folder/lib/bfd-plugins ]
then
    mkdir $futag_install_folder/lib/bfd-plugins
fi
cp lib/LLVMgold.so $futag_install_folder/lib/bfd-plugins
cp lib/libLTO.so $futag_install_folder/lib/bfd-plugins

export PATH="$(pwd)/bin:$PATH"
export LLVM_CONFIG="$(pwd)/bin/llvm-config"
export LD_LIBRARY_PATH="$(llvm-config --libdir)${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

#build AFLplusplus
cd AFLplusplus-4.02c
make -j8 distrib
make -j8 DESTDIR=$futag_install_folder/AFLplusplus install
cd ..

if [ -d $futag_install_folder/python-package ]
then
    rm -rf $futag_install_folder/python-package
fi
mkdir $futag_install_folder/python-package
cp -r $futag_src/python/futag-package/dist/*.tar.gz $futag_install_folder/python-package
cp -r $futag_src/python/futag-package/requirements.txt $futag_install_folder/python-package
cp -r $futag_src/svres-tmpl $futag_install_folder/
cp -r ../*.md $futag_install_folder/
cp -r ../LICENSE $futag_install_folder/
cp $custom_prepare/INFO $futag_install_folder/

cd ../product-tests
XZ_OPT='-T8 -9' tar cJf futag-llvm$version.AFLplusplus.fuzz-introspector.latest.tar.xz ../futag-llvm

echo ""
echo "======== End of build script for FUTAG - a Fuzz target automated generator ========"
echo 