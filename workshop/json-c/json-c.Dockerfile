# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

#Download base image ubuntu 24.04
FROM ubuntu:24.04

LABEL maintainer="thientcgithub@gmail.com"
LABEL description="This is custom Docker Image based on Ubuntu 24.04 for testing Futag."

RUN apt update --fix-missing
RUN export DEBIAN_FRONTEND=noninteractive
RUN ln -fs /usr/share/zoneinfo/Europe/Moscow /etc/localtime
RUN apt-get install -y tzdata
RUN apt install -y apt-utils libncurses-dev gcc gcc-multilib binutils binutils-gold binutils-dev g++ make gdb openssh-client git wget xz-utils python3 python3-pip python-is-python3  nano cmake libtool texinfo libbison-dev unzip automake autoconf 

WORKDIR /root

#install Futag binaries
RUN wget https://github.com/ispras/Futag/releases/download/v3.0.0/futag-llvm18.u24.latest.tar.xz
RUN tar xf futag-llvm18.u24.latest.tar.xz
#install Futag python package
RUN wget https://github.com/ispras/Futag/releases/download/v3.0.0/futag-3.0.0.tar.gz
RUN pip3 install --break-system-packages futag-3.0.0.tar.gz

#download json-c source code
RUN mkdir json-c
WORKDIR /root/json-c

RUN wget https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz
RUN tar -xvf json-c-0.18-20240915.tar.gz

# Crawl test script futag.all-in-one.py
RUN wget https://raw.githubusercontent.com/ispras/Futag/refs/heads/llvm18/workshop/json-c/futag.all-in-one.py
#automatically test json-c with Futag

RUN python3 futag.all-in-one.py

#docker build --network=host -t futag-json-c:0.18 -f .\json-c.Dockerfile .
#docker run -it --rm --privileged --network host -v `pwd`:/host futag-json-c:0.18 /bin/bash