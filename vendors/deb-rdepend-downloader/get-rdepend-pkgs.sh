#!/bin/bash

# This script helps to download all depending packages in source list.
# Using: <get-rdepends-pkgs> [name-of-package]

dependencies_folder="dependencies"
pkg_name=$1

if [ ! -d "$pkg_name" ] 
then
    mkdir "$pkg_name"
fi
cd "$pkg_name"

apt-get source $pkg_name

if [ ! -d "$dependencies_folder" ] 
then
    mkdir "$dependencies_folder"
fi
cd "$dependencies_folder"

echo "Getting depending packages of $pkg_name ..."
apt-cache rdepends $pkg_name | awk 'NR > 2 {pos=index($1,"|"); print substr($1,pos+1) }' | xargs -i bash -c "apt-get source {} || true"  