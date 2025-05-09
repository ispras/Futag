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
llvmVersion=(1 2 3)
if [ $# -eq 0 ]; then
    echo "Futag will collect information for preparing build system."
    echo "========================================================="
    echo "-- [Futag] Select version of llvm for building:"
    echo "-- 1. LLVM 18.1.0"
    echo "-- 2. LLVM 14.0.6"
    echo "-- 3. LLVM 13.0.1"
    
    read -p "-- Your choice (1/2/3 - default to 1): " selectedVersion 
    if [[ ! " ${llvmVersion[*]} " =~ " ${selectedVersion} " ]]; then
        echo "-- [Futag] Wrong input! Please enter 1 or 2! Exit..."
        exit
    fi
    echo "========================================================="

else
    selectedVersion=$1
    if [[ ! " ${llvmVersion[*]} " =~ " ${selectedVersion} " ]]; then
        echo
        echo "-- [Futag] Wrong input! Please enter 1 or 2! Exit..."
        echo
        exit
    fi
fi
# https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/4.02c.tar.gz

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

if [ "$selectedVersion" == "1" ]; then
# Alt Linux 11 with llvm-project 18.1 
# https://www.altlinux.org/%D0%9E%D0%B4%D0%B8%D0%BD%D0%BD%D0%B0%D0%B4%D1%86%D0%B0%D1%82%D0%B0%D1%8F_%D0%BF%D0%BB%D0%B0%D1%82%D1%84%D0%BE%D1%80%D0%BC%D0%B0
# https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.0/llvm-project-18.1.0.src.tar.xz
    echo "LLVM=18.1.0" > $file_info
    if [ ! -f llvm-project-18.1.0.src.tar.xz ]; then
        wget https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.0/llvm-project-18.1.0.src.tar.xz
    fi
    tar xf llvm-project-18.1.0.src.tar.xz
    mv llvm-project-18.1.0.src llvm-project
fi

if [ "$selectedVersion" == "2" ]; then
    echo "LLVM=14.0.6" > $file_info
    if [ ! -f llvm-project-14.0.6.src.tar.xz ]; then
        wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/llvm-project-14.0.6.src.tar.xz
    fi
    tar xf llvm-project-14.0.6.src.tar.xz
    mv llvm-project-14.0.6.src llvm-project
fi

if [ "$selectedVersion" == "3" ]; then
    echo "LLVM=13.0.1" > $file_info
    if [ ! -f llvm-project-13.0.1.src.tar.xz ]; then
        wget https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.1/llvm-project-13.0.1.src.tar.xz
    fi
    tar xf llvm-project-13.0.1.src.tar.xz
    mv llvm-project-13.0.1.src llvm-project
fi

build_script="build.sh"

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
