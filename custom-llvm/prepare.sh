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
if ! [ -f "llvm-11.1.0.src.tar.xz" ]
then
    wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/llvm-11.1.0.src.tar.xz
fi
tar xf llvm-11.1.0.src.tar.xz
if [ -d "llvm" ]
then
    rm -rf llvm
fi
mv llvm-11.1.0.src llvm

# Download clang source code
if ! [ -f "clang-11.1.0.src.tar.xz" ]
then
    wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/clang-11.1.0.src.tar.xz
fi

tar xf clang-11.1.0.src.tar.xz
if [ -d "clang" ]
then
    rm -rf clang
fi
mv clang-11.1.0.src clang

# Download compiler-rt source code
if ! [ -f "compiler-rt-11.1.0.src.tar.xz" ]
then
    wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/compiler-rt-11.1.0.src.tar.xz
fi

tar xf compiler-rt-11.1.0.src.tar.xz
if [ -d "compiler-rt" ]
then
    rm -rf compiler-rt
fi
mv compiler-rt-11.1.0.src compiler-rt

#create build folder and copy script
if [ -d "../build" ]
then
    rm -rf ../build
fi
mkdir ../build
cp build.sh ../build