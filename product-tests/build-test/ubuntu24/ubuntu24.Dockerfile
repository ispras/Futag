#Download base image ubuntu 22.04
FROM ubuntu:24.04

LABEL maintainer="thientc84@gmail.com"
LABEL description="This is custom Docker Image based on Ubuntu 22.04 for testing Futag."

RUN apt update --fix-missing
RUN apt install -y apt-utils
RUN useradd -ms /bin/bash futag
#Установка необходимых библиотек для futag
RUN apt install -y libncurses-dev gcc-multilib g++ make gdb binutils python3 git openssh-client cmake wget xz-utils python3-pip texinfo binutils-gold binutils-dev  gcc-13-plugin-dev automake autoconf
 
USER futag
WORKDIR /home/futag/
RUN git clone https://github.com/ispras/Futag.git
# RUN git clone --depth 1 https://github.com/ispras/Futag.git
WORKDIR /home/futag/Futag/
RUN git checkout llvm18
WORKDIR /home/futag/Futag/custom-llvm
RUN ./prepare.sh 1
RUN pwd
WORKDIR /home/futag/Futag/build
RUN ./build.sh

USER root
WORKDIR /home/futag/Futag/
