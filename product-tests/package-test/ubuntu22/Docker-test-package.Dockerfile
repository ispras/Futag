#Download base image ubuntu 22.04
FROM ubuntu:22.04

LABEL maintainer="thientc84@gmail.com"
LABEL description="This is custom Docker Image based on Ubuntu 22.04 for testing Futag."

RUN apt update --fix-missing
RUN apt install -y apt-utils
RUN useradd -ms /bin/bash futag

#Установка необходимых библиотек для futag
RUN apt install -y libncurses5 gcc-multilib g++ make gdb binutils python3 git openssh-client cmake wget xz-utils python3 python3-pip texinfo libbison-dev nano

USER futag
WORKDIR /home/futag/
ADD futag-llvm.latest.tar.xz /home/futag/

USER root
WORKDIR /home/futag/Futag/
RUN pip install futag-llvm/python-package/futag-1.1.tar.gz
RUN pip install -r futag-llvm/python-package/requirements.txt

USER futag 
WORKDIR /home/futag/Futag/