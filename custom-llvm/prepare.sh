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

set -x 

futag_install_folder="$(pwd)/../futag-llvm"
build_folder="$(pwd)/../build"

if [ -d "AFLplusplus-4.02c" ]
then
    rm -rf AFLplusplus-4.02c
fi

if [ -d "fuzz-introspector" ]
then
    rm -rf fuzz-introspector
fi

if [ -f llvm-project-14.0.6.src.tar.xz ]
then
    rm llvm-project-14.0.6.src.tar.xz
fi

if [ -d "llvm-project-14.0.6.src" ]
then
    rm -rf llvm-project-14.0.6.src
fi

#create build folder and copy script
if [ -d $build_folder ]
then
    rm -rf $build_folder
fi
mkdir $build_folder

#getting llvm-project 
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/llvm-project-14.0.6.src.tar.xz

for f in *.tar.*; do tar xf "$f"; done

# create futag installation folder
if [ -d $futag_install_folder ]
then
    rm -rf $futag_install_folder
fi
mkdir $futag_install_folder

# begin integrate with fuzz-introspector
# extract and build binutils
binutils_build="binutils-build"

mv binutils $build_folder/
# git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils

set +x 
mv fuzz-introspector $futag_install_folder/
cp build*.sh  $build_folder
