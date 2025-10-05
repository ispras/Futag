# Futag Workshop

## 1. Introduction

- [Slide: Раскрытие секрета инструмента Futag.pptx](./Раскрытие%20секрета%20инструмента%20Futag.pptx)

## 2. An ease way of automatic testing

- Some useful examples of using Futag to test your library: https://github.com/thientc/Futag-tests

- Steps to use Futag to test your library:
  - Download Futag package from github (https://github.com/ispras/Futag/releases)
  - Install dependencies (https://github.com/ispras/Futag/blob/main/product-tests/libraries-test/ubuntu22/Docker-test-libs.Dockerfile)
  - Install Futag python-package (It's better to use virtualenv)
  - Download and extract you library
  - Create test script (https://github.com/thientc/Futag-tests/blob/main/json-c/build.py)
  - Have a cup of coffee and wait for the result

## 3. Let's helf Futag to understand your library 
Preparation
- Download Futag package from github
- Download  

- VirtualBox and alt11 install
- Install dependencies
```bash
apt-get install -y make gdb binutils python3 git gcc cmake wget texinfo automake autoconf bash-completion  gcc-c++* gcc-common python3-module-pip openssh-clients xz binutils-devel meson
```
- Install dependencies for libvirt
```bash
apt-get install -y   libudev-devel   libyajl-devel   sanlock-devel  libpcap-devel  libnl-devel  libselinux-devel  libsasl2-devel  polkit  util-linux  qemu-img  lvm2  libparted-devel parted libuuid-devel dmsetup ceph-devel  open-iscsi  libiscsi-devel  libdevmapper-devel  libglusterfs-devel  libnuma-devel   libcap-ng-devel  libcurl-devel   libaudit-devel  libfuse-devel   libnbd-devel  pm-utils  glib2-devel wireshark tshark wireshark-devel  libblkid-devel  libgcrypt-devel libgnutls-devel libp11-kit-devel  libreadline-devel  libtasn1-devel  libattr-devel attr  libacl-devel  glib2-devel  libgio-devel  libxml2-devel xml-utils xsltproc  python3 python3-devel python3-module-pytest  python3-module-docutils  zlib-devel  iproute2  dmidecode  libtirpc-devel  glibc-utils  kmod  mdevctl udev
```
- libvirt source code from https://packages.altlinux.org/en/p11/srpms/rpm/rpms/
- Build command:
```bash
rpm -ba ~/RPM/SPECS/libvirt.spec
```

~/Futag/futag-llvm/bin/scan-build  -disable-checker core -disable-checker security -disable-checker unix -disable-checker deadcode -disable-checker nullability -disable-checker cplusplus -enable-checker futag.FutagAnalyzer -analyzer-config futag.FutagAnalyzer:report_dir=/home/thientc/libvirt/analysis_result gear-rpm -bc


~/Futag/futag-llvm/bin/scan-build -disable-checker core -disable-checker security -disable-checker unix -disable-checker deadcode -disable-checker nullability -disable-checker cplusplus -enable-checker futag.FutagAnalyzer -analyzer-config futag.FutagAnalyzer:report_dir=futag-analysis ./build.sh

/home/thientc/RPM/BUILD/libvirt-10.7.0/x86_64-alt-linux/futag-analysis

https://packages.altlinux.org/ru/p11/srpms/libvirt/rpms/

https://git.altlinux.org/tasks/356646/build/15700/x86_64/srpm/libvirt-10.7.0-alt1.src.rpm

