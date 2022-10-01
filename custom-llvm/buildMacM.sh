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

futag_src="../src"
futag_install_folder="../futag-llvm"
vendors="../vendors"
custom_llvm="../custom-llvm"

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

# on Macbook with M1, M2 processors, you should install g++-11 to avoid error with clang14 (default install for MacOS > 12.5)
cmake  -G "Unix Makefiles" -DCMAKE_CXX_COMPILER=/opt/homebrew/bin/g++-11 -DCMAKE_C_COMPILER=/opt/homebrew/bin/gcc-11 -DLLVM_BUILD_TESTS=OFF -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_ENABLE_ZLIB=OFF -DCMAKE_BUILD_TYPE=Release -DLLVM_BINUTILS_INCDIR=./binutils/futag-install/include -DLLVM_INSTALL_TOOLCHAIN_ONLY=On -DCMAKE_INSTALL_PREFIX=$futag_install_folder -DLLVM_INCLUDE_BENCHMARKS=OFF  -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;" $custom_llvm/llvm

make -j8 && make -j8 install

cp lib/LLVMgold.so $futag_install_folder/lib/
mkdir $futag_install_folder/lib/bfd-plugins
cp lib/LLVMgold.so $futag_install_folder/lib/bfd-plugins
cp lib/libLTO.so $futag_install_folder/lib/bfd-plugins

cp -r $custom_llvm/AFLplusplus $futag_install_folder/

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
