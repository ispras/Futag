#Download base image ubuntu 20.04
FROM ubuntu:20.04

LABEL maintainer="thientc84@gmail.com"
LABEL description="This is custom Docker Image based on Ubuntu 20.04 for testing Futag."

RUN apt update --fix-missing
RUN apt install -y apt-utils
RUN useradd -ms /bin/bash futag
RUN export DEBIAN_FRONTEND=noninteractive
RUN ln -fs /usr/share/zoneinfo/Europe/Moscow /etc/localtime
RUN apt-get install -y tzdata

#Установка необходимых библиотек для futag
RUN apt install -y libncurses5 libtinfo5 gcc-multilib g++ make gdb binutils binutils-gold binutils-dev python3 python3-pip python-is-python3 git openssh-client cmake wget xz-utils python3-pip texinfo libbison-dev nano gcc-9-plugin-dev automake autoconf

USER futag
WORKDIR /home/futag/
RUN git clone --depth 1 https://github.com/ispras/Futag.git
WORKDIR /home/futag/Futag/custom-llvm
RUN ./prepare.sh 1
WORKDIR /home/futag/Futag/build
RUN ./build.sh

USER root
WORKDIR /home/futag/Futag/
RUN pip install futag-llvm/python-package/futag-2.0.1.tar.gz
RUN pip install -r futag-llvm/python-package/requirements.txt

USER futag 
WORKDIR /home/futag/Futag/