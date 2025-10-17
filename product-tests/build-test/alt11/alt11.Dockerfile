#Download base image alt11
FROM alt:p11

LABEL maintainer="thientc84@gmail.com"
LABEL description="This is custom Docker Image based on Alt Linux 11 for testing Futag with LLVM 18."

RUN apt-get update --fix-missing
RUN apt-get install -y apt-utils
RUN useradd -ms /bin/bash futag
#Установка необходимых библиотек для futag
RUN apt-get install -y make gdb binutils python3 git gcc cmake wget texinfo automake autoconf bash-completion  gcc-c++* gcc-common python3-module-pip openssh-clients xz binutils-devel
WORKDIR /home/futag/
RUN pwd
RUN git clone https://github.com/ispras/Futag.git
WORKDIR /home/futag/Futag/
RUN git checkout llvm18
WORKDIR /home/futag/Futag/custom-llvm
RUN ./prepare.sh 2
WORKDIR /home/futag/Futag/build
RUN ./build.sh
