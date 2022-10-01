#!/bin/bash

#===-- build.bash -------*- bash script -*-===//
#
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).
#
# This script helps to download source code of clang, llvm, compiler-rt (from https://github.com/llvm/llvm-project/releases/tag/llvmorg-11.1.0)


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
echo "* This script helps to download source code of *"
echo "*            clang, llvm, compiler-rt          *"
echo "************************************************"

futag_src="../src"
futag_install_folder="../futag-llvm"
vendors="../vendors"
custom_llvm="../custom-llvm"
build_folder="../build"
binutils_build="binutils-build"

cd $build_folder
cd binutils
mkdir $binutils_build
mkdir binutils-install
curr_dir="$PWD"

cd $binutils_build

../configure --prefix=$curr_dir/binutils-install --enable-gold --enable-plugins --disable-werror
make -j8 all-gold
make -j8 install

futag_install_folder="../futag-llvm"

fuzz_introspector=$futag_install_folder/fuzz-introspector

$fuzz_introspector/sed_cmds.sh
cd $custom_llvm
cp -rf $fuzz_introspector/frontends/llvm/include/llvm/Transforms/FuzzIntrospector/ ./llvm/include/llvm/Transforms/FuzzIntrospector
cp -rf $fuzz_introspector/frontends/llvm/lib/Transforms/FuzzIntrospector ./llvm/lib/Transforms/FuzzIntrospector

#copy source code to llvm-project
cp -r $vendors/json-3.10.5/single_include/nlohmann $custom_llvm/clang/include/

cp -r $futag_src/clang/include/clang/ASTMatchFinder.h $custom_llvm/clang/include/clang/ASTMatchers/
cp -r $futag_src/clang/lib/clang/ASTMatchFinder.cpp $custom_llvm/clang/lib/ASTMatchers/


cp -r $futag_src/clang/include/Futag $custom_llvm/clang/include/
cp $futag_src/clang/lib/CMakeLists.txt $custom_llvm/clang/lib/
cp -r $futag_src/clang/lib/Futag $custom_llvm/clang/lib/

# copy clang Checker
cp -r $futag_src/Checkers/include/Checkers.td $custom_llvm/clang/include/clang/StaticAnalyzer/Checkers/
cp -r $futag_src/Checkers/lib/* $custom_llvm/clang/lib/StaticAnalyzer/Checkers/

cmake  -G "Unix Makefiles" \
    -DLLVM_BUILD_TESTS=OFF \
    -DLLVM_TARGETS_TO_BUILD=X86 \
    -DLLVM_ENABLE_ZLIB=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_BINUTILS_INCDIR=/usr/include/
    -DLLVM_INSTALL_TOOLCHAIN_ONLY=On \
    -DCMAKE_INSTALL_PREFIX=$futag_install_folder \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
    -DCLANG_INCLUDE_DOCS="OFF" \
    -DLLVM_BUILD_LLVM_DYLIB="ON" \
    -DLLVM_ENABLE_BINDINGS="OFF" \
    -DLLVM_ENABLE_PROJECTS='clang;compiler-rt;libcxx;libcxxabi;libunwind;lld' \
    -DLLVM_ENABLE_WARNINGS="OFF" \
    -DLLVM_INCLUDE_BENCHMARKS="OFF" \
    -DLLVM_INCLUDE_DOCS="OFF" \
    -DLLVM_INCLUDE_EXAMPLES="OFF" \
    -DLLVM_INCLUDE_TESTS="OFF" \
    -DLLVM_LINK_LLVM_DYLIB="ON" \
    -DLLVM_TARGETS_TO_BUILD="host" \
    $custom_llvm/llvm

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
mv $custom_llvm/AFLplusplus .
cd AFLplusplus
make -j8 DESTDIR=$futag_install_folder/AFLplusplus install
cd ..

if [ -d $futag_install_folder/python-package ]
then
    rm -rf $futag_install_folder/python-package
fi
mkdir $futag_install_folder/python-package
cp -r $futag_src/python/futag-package/dist/*.tar.gz $futag_install_folder/python-package
cp -r $futag_src/python/requirements.txt $futag_install_folder/python-package
cp -r $futag_src/svres-tmpl $futag_install_folder/
cp -r ../*.md $futag_install_folder/
cp -r ../LICENSE $futag_install_folder/

cd ../product-tests
./prepare-package.sh

echo ""
echo "======== End of install script for FUTAG - a fuzzing target automated generator ========"
echo ""
