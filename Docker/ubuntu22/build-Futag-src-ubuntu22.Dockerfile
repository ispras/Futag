#Download base image ubuntu 20.04
FROM ubuntu:22.04

LABEL maintainer="thientc84@gmail.com"
LABEL description="This is custom Docker Image based on Ubuntu 20.04 for testing Futag."

RUN apt update --fix-missing
RUN apt install -y apt-utils
RUN useradd -ms /bin/bash futag
# RUN export DEBIAN_FRONTEND=noninteractive
# RUN ln -fs /usr/share/zoneinfo/Europe/Moscow /etc/localtime
# RUN apt-get install -y tzdata
# RUN dpkg-reconfigure --frontend noninteractive tzdata
# RUN apt-get install -y libfile-dircompare-perl

#Установка необходимых библиотек для futag
RUN apt install -y libncurses5 gcc-multilib g++ make gdb binutils python3 git openssh-client nano cmake wget xz-utils 
USER futag
WORKDIR /home/futag/

RUN git clone https://github.com/ispras/Futag.git
WORKDIR /home/futag/Futag
RUN git checkout testing-libs
WORKDIR /home/futag/Futag/custom-llvm
RUN ./prepare14.sh
WORKDIR /home/futag/Futag/build
RUN ./build.sh

