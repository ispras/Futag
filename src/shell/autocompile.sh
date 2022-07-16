#!/bin/bash

# This script tries to automatically configure and compile downloaded Debian packages.
# Using: <autocompile.sh> inside package folder of get-rdepend-pkgs.sh

[ ! -z "$1" ] && cd "$1"

CC="/home/Futag/futag-public-package/bin/clang"
CXX="/home/Futag/futag-public-package/bin/clang++"
CFLAGS="-g -O0 -fsanitize=address"
CXXFLAGS="-g -O0 -fsanitize=address"
LDFLAGS="-g -O0 -fsanitize=address"

SCANBUILD="/home/Futag/futag-public-package/bin/scan-build"

export CC="/home/Futag/futag-public-package/bin/clang"
export CXX="/home/Futag/futag-public-package/bin/clang++"
export CFLAGS="-g -O0 -fsanitize=address"
export CXXFLAGS="-g -O0 -fsanitize=address"
export LDFLAGS="-g -O0 -fsanitize=address"

process=12

dependencies_folder="dependencies"
cd "$dependencies_folder"

build_folder="build-futag"
ls -d */ > .subfolder.tmp

while IFS= read -r subfolder
do
    echo "Change to $subfolder!"
    cd "$subfolder"
    if [ ! -d "$build_folder" ]
    then
        echo "-- Making directory: $build_folder"
        mkdir $build_folder
    fi
    if [ ! -d "$build_folder/futag-install" ]
    then
        echo "-- Making directory: $build_folder/futag-install"
        mkdir "$build_folder/futag-install"
    fi
    
    if [ -f "configure" ]; then
        cd $build_folder
        full_prefix=$(realpath $(find . -name "*futag-install" -type d))
        echo $full_prefix
        ../configure --prefix=$full_prefix CC="$CC" CFLAGS="$CFLAGS" CXX="$CXX" CXXFLAGS="$CXXFLAGS" LDFLAGS="$LDFLAGS"
        make clean && "$SCANBUILD" -enable-checker futag make -j"$process" && make install
        cd ..
    else
        if [ -f "CMakeLists.txt" ]; then
            cd $build_folder
            cmake -G "Unix Makefiles" -DCMAKE_PREFIX_PATH=$full_prefix -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$CFLAGS"  -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_CXX_FLAGS="$CXXFLAGS" ..
            make clean && "$SCANBUILD" -enable-checker futag make -j"$process" && make install
            cd ..
        fi
    fi
    cd ..
    echo
    echo
done < ".subfolder.tmp"

