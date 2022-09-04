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

# Download llvm source code
if ! [ -f "llvm-14.0.6.src.tar.xz" ]
then
    wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/llvm-14.0.6.src.tar.xz
fi

tar xf llvm-14.0.6.src.tar.xz

if [ -d "llvm" ]
then
    rm -rf llvm
fi
mv llvm-14.0.6.src llvm

# Download clang source code
if ! [ -f "clang-14.0.6.src.tar.xz" ]
then
    wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/clang-14.0.6.src.tar.xz 
fi

tar xf clang-14.0.6.src.tar.xz 

if [ -d "clang" ] 
then
    rm -rf clang 
fi
mv clang-14.0.6.src clang

# # Download clang-tools-extra source code
# if ! [ -f "clang-tools-extra-11.1.0.src.tar.xz" ]
# then
#     wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/clang-tools-extra-11.1.0.src.tar.xz
# fi

# tar xf clang-tools-extra-11.1.0.src.tar.xz
# if [ -d "clang-tools-extra" ]
# then
#     rm -rf clang-tools-extra
# fi
# mv clang-tools-extra-11.1.0.src clang-tools-extra

# Download compiler-rt source code
if ! [ -f "compiler-rt-14.0.6.src.tar.xz" ]
then
    wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/compiler-rt-14.0.6.src.tar.xz
fi

tar xf compiler-rt-14.0.6.src.tar.xz
if [ -d "compiler-rt" ]
then
    rm -rf compiler-rt
fi
mv compiler-rt-14.0.6.src compiler-rt

#create build folder and copy script
if [ -d "../build" ]
then
    rm -rf ../build
fi
mkdir ../build
cp build.sh ../build