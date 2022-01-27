#Download base image ubuntu 20.04
FROM ubuntu:20.04

LABEL maintainer="thientc@ispras.ru"
LABEL description="This is custom Docker Image based on Ubuntu 20.04 for testing Futag."

RUN apt update --fix-missing
RUN apt install -y apt-utils
RUN useradd -ms /bin/bash futag

#Установка необходимых библиотек для futag
RUN apt install -y libncurses5 gcc-multilib g++ make gdb binutils python3

#Установка необходимых библиотек для curl
RUN apt install -y libssl-dev zlib1g-dev wget libpsl-dev libgsasl7-dev libldap-dev

#Получение curl-7_79_1
USER futag
WORKDIR /home/futag/
RUN wget https://github.com/curl/curl/releases/download/curl-7_79_1/curl-7.79.1.tar.gz
RUN tar -xf curl-7.79.1.tar.gz
RUN mkdir curl-7.79.1/build
RUN mkdir curl-7.79.1/build/local-install

#Добавление пакет futag (futag-package) в докер-контейнер
ADD futag /home/futag/futag

#сборка и устнановка curl-7_79_1
WORKDIR /home/futag/curl-7.79.1/build
RUN ../configure --with-openssl --prefix=/home/futag/curl-7.79.1/build/local-install  CC=/home/futag/futag/bin/clang CFLAGS="-fsanitize=address -fprofile-instr-generate -fcoverage-mapping -g -O0" LDFLAGS="-fsanitize=address -g -O0"
RUN make -j4
RUN make -j4 install

#Использование futag для автоматической генерации фаззинг-оберток, запуска и сборки результатов фаззинга
WORKDIR /home/futag/curl-7.79.1/build/local-install
RUN python3 ~/futag/tools/futag-run.py -a lib -i ". include include/curl" -o targetscurl  -s "-lgsasl -lpsl -lssl -lcrypto -lssl -lcrypto -lldap -llber -lz" -tt 120 -f 4 -m 8000 include/curl/curl.h