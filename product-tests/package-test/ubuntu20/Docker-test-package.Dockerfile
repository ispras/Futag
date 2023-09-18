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
RUN apt install -y libncurses5 libtinfo5 gcc-multilib g++ make gdb binutils python3 git openssh-client cmake wget xz-utils python3 python3-pip texinfo libbison-dev nano

USER futag
WORKDIR /home/futag/
ADD futag-llvm.latest.tar.xz /home/futag/Futag/

USER root
WORKDIR /home/futag/Futag/
RUN pip install futag-llvm/python-package/futag-2.1.0.tar.gz
RUN pip install -r futag-llvm/python-package/requirements.txt

USER futag 
WORKDIR /home/futag/Futag/
