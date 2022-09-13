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

futag_install_folder="../futag-llvm-package"
build_folder="../build"
if [ -d "llvm" ]
then
    rm -rf llvm
fi
tar xf llvm-14.0.6.src.tar.xz
mv llvm-14.0.6.src llvm

if [ -d "clang" ]
then
    rm -rf clang
fi
tar xf clang-14.0.6.src.tar.xz
mv clang-14.0.6.src clang

if [ -d "compiler-rt" ]
then
    rm -rf compiler-rt
fi
tar xf compiler-rt-14.0.6.src.tar.xz
mv compiler-rt-14.0.6.src compiler-rt

#create build folder and copy script
if [ -d $build_folder ]
then
    rm -rf $build_folder
fi
mkdir $build_folder

# create futag installation folder
if [ -d $futag_install_folder ]
then
    rm -rf $futag_install_folder
fi
mkdir $futag_install_folder

# extract and build binutils
binutils_install="binutils-install"
tar xf binutils-futag.tar.xz -C $build_folder/

cd $build_folder

mkdir $binutils_install
cd $binutils_install
mkdir local-install
curr_dir="$PWD"
../binutils/configure --prefix=$curr_dir/local-install --enable-gold --enable-plugins --disable-werror
make -j8 all-gold
make -j8 install
cd ..

set +x 
cd ../custom-llvm/

tar xf fuzz-introspector.tar.xz -C $futag_install_folder/
fuzz_introspector=$futag_install_folder/fuzz-introspector

$fuzz_introspector/sed_cmds.sh
cp -rf $fuzz_introspector/frontends/llvm/include/llvm/Transforms/FuzzIntrospector/ ./llvm/include/llvm/Transforms/FuzzIntrospector
cp -rf $fuzz_introspector/frontends/llvm/lib/Transforms/FuzzIntrospector ./llvm/lib/Transforms/FuzzIntrospector

cp build.sh $build_folder
