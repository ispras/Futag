#Download base image alt11
FROM alt:p11

LABEL maintainer="thientc84@gmail.com"
LABEL description="This is custom Docker Image based on Alt Linux 11 for testing Futag."

RUN apt-get update 
RUN apt-get install -y apt-utils
RUN useradd -ms /bin/bash futag
#Установка необходимых библиотек для futag
RUN apt-get install -y make gdb binutils python3 git gcc cmake wget texinfo automake autoconf bash-completion gcc-c++* gcc-common python3-module-pip openssh-clients xz binutils-devel wget python3-module-distutils-extra perl-Term-ANSIColor meson

WORKDIR /home/futag/
USER futag
RUN mkdir Futag
RUN wget https://github.com/ispras/Futag/releases/download/v3.0.0/futag-llvm18.alt11.tar.xz
RUN tar xf futag-llvm18.alt11.tar.xz
RUN mv futag-llvm Futag/
RUN wget https://github.com/ispras/Futag/releases/download/v3.0.0/futag-3.0.0.tar.gz
USER root
RUN pip3 install futag-3.0.0.tar.gz

USER futag
RUN git clone https://github.com/thientc/Futag-tests.git

# Пример для сборки библиотеки libdwarf
WORKDIR /home/futag/Futag-tests/libdwarf
RUN ./prepare.sh
# Здесь возможно добавить необходимые пакеты для сборки
# RUN apt-get install -y ...
# Сборка с помощью Futag 
RUN python3 build.py
