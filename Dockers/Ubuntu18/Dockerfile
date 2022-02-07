#Download base image ubuntu 18.04
FROM ubuntu:18.04

LABEL maintainer="thientc@ispras.ru"
LABEL description="This is custom Docker Image for using Futag."

RUN apt update --fix-missing
RUN apt install -y apt-utils
RUN useradd -ms /bin/bash futag

#Установка необходимых библиотек для futag
RUN apt install -y libncurses5 libgcc-5-dev make gdb binutils python3 git openssh-client nano cmake

USER futag
WORKDIR /home/futag/

RUN git clone --recurse-submodules https://github.com/ispras/Futag.git
WORKDIR /home/futag/Futag
RUN mkdir build
WORKDIR /home/futag/Futag/build
RUN cp ../build.bash .
RUN ./build.bash
