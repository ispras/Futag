# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

#Download base image alt11
FROM alt:p11
LABEL maintainer="thientc84@gmail.com"
LABEL description="This is custom Docker Image based on Alt Linux 11 for testing Futag."

RUN apt-get update --fix-missing
RUN apt-get install -y apt-utils
#Установка необходимых библиотек для futag
RUN apt-get update --fix-missing
RUN apt-get install -y make gdb binutils python3 git gcc cmake wget texinfo automake autoconf bash-completion  gcc-c++* gcc-common python3-module-pip openssh-clients xz binutils-devel
WORKDIR /home/futag/
RUN mkdir Futag
RUN wget https://github.com/ispras/Futag/releases/download/v3.0.0/futag-llvm18.alt11.latest.tar.xz
RUN tar futag-llvm18.alt11.latest.tar.xz
RUN mv futag-llvm Futag/
RUN wget https://github.com/ispras/Futag/releases/download/v3.0.0/futag-3.0.0.tar.gz
USER root
RUN pip3 install futag-3.0.0.tar.gz
RUN wget https://git.altlinux.org/tasks/356646/build/15700/x86_64/srpm/libvirt-10.7.0-alt1.src.rpm
RUN apt-get install -y rpm-build
RUN rpm -i libvirt-10.7.0-alt1.src.rpm
RUN mkdir test_libvirt
RUN rpm -ba RPM/SPECS/libvirt.spec
RUN ~/Futag/futag-llvm/bin/scan-build -disable-checker core -disable-checker security -disable-checker unix -disable-checker deadcode -disable-checker nullability -disable-checker cplusplus -enable-checker futag.FutagAnalyzer -analyzer-config futag.FutagAnalyzer:report_dir=~/test_libvirt/futag-analysis rpm -ba RPM/SPECS/libvirt.spec


#docker build --network=host -t futag-libvirt -f .\libvirt-alt11.Dockerfile .
#docker run -it --rm --privileged --network host -v `pwd`:/host futag-libvirt /bin/bash