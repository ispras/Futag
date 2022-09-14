#Download base image ubuntu 20.04
FROM ubuntu:22.04

LABEL maintainer="thientc84@gmail.com"
LABEL description="This is custom Docker Image based on Ubuntu 20.04 for testing Futag."

RUN apt update --fix-missing
RUN apt install -y apt-utils
RUN useradd -ms /bin/bash futag

#Установка необходимых библиотек для futag
RUN apt install -y libncurses5 gcc-multilib g++ make gdb binutils python3 git openssh-client cmake wget xz-utils 
RUN apt install -y python3 python3-pip

USER futag
WORKDIR /home/futag/
RUN git clone --depth 1 https://github.com/ispras/Futag.git

USER root
RUN pip install pathlib
RUN apt install -y texinfo

USER futag
WORKDIR /home/futag/Futag/custom-llvm
RUN ./prepare.sh
WORKDIR /home/futag/Futag/build
RUN ./build.sh

USER root
WORKDIR /home/futag/Futag/

RUN pip install -r futag-llvm-package/fuzz-introspector/requirements.txt

