#!/bin/bash

#===-- build.bash ======-*- bash script -*-===//
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
echo 
read -p "-- [Futag] Build with AFLplusplus-4.02c? (y/n): " wAFLplusplus
if [[ ! $wAFLplusplus == [yYnN] ]]; then
    echo "-- [Futag] Wrong input! Please enter y or n! Exit..."
    exit
fi

# # https://github.com/ossf/fuzz-introspector/archive/refs/tags/v1.0.0.tar.gz
# echo "========================================================="
# read -p "-- [Futag] Build with fuzz-introspector? (y/n): " fuzzintro
# if [[ ! $fuzzintro == [yYnN] ]]; then
#     echo "-- [Futag] Wrong input! Please enter y or n! Exit..."
#     exit
# fi
# echo "========================================================="
# echo
echo "-- [Futag] Preparing .. "

futag_install_folder="$(pwd)/../futag-llvm"
build_folder="$(pwd)/../build"

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

#write infomation of build to file INFO
file_info="INFO"
set -x
if [ -d "llvm-project" ]; then
    rm -rf llvm-project
fi
if [ ! -f llvm-project-14.0.6.src.tar.xz ]; then
    wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/llvm-project-14.0.6.src.tar.xz
fi
tar xf llvm-project-14.0.6.src.tar.xz
mv llvm-project-14.0.6.src llvm-project
build_script="build.sh"

if [ $wAFLplusplus == "Y" ] || [ $wAFLplusplus == "y" ]; then
    echo "AFLplusplus=yes" >> $file_info
    if [ -d AFLplusplus-4.02c ]; then
        rm -rf AFLplusplus-4.02c
    fi
    if [ ! -f 4.02c.tar.gz ]; then
        wget https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/4.02c.tar.gz
    fi
    tar xf 4.02c.tar.gz
    mv AFLplusplus-4.02c $build_folder/
    build_script="buildwAFLplusplus.sh"
else
    echo "AFLplusplus=no" >> $file_info
fi

# if [ $fuzzintro == "Y" ] || [ $fuzzintro == "y" ]; then
#     echo "FuzzIntrospector=yes" >> $file_info
#     if [ -d fuzz-introspector-1.0.0 ]; then
#         rm -rf fuzz-introspector-1.0.0
#     fi
#     if [ ! -f v1.0.0.tar.gz ]; then
#         wget https://github.com/ossf/fuzz-introspector/archive/refs/tags/v1.0.0.tar.gz
#     fi
#     tar xf v1.0.0.tar.gz
#     cp -r fuzz-introspector-1.0.0 $futag_install_folder/
#     if [ $wAFLplusplus == "Y" ] || [ $wAFLplusplus == "y" ]; then
#         build_script="buildwAFLplusplusFuzzIntro.sh"
#     else
#         build_script="buildwFuzzIntro.sh"
#     fi
# else
#     echo "FuzzIntrospector=no" >> $file_info
# fi
cp $build_script  $build_folder/build.sh
