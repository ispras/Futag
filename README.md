# Table of Contents

- 1. [About](#about)
- 2. [Quick start with Dockers](#quick_start)
- 3. [Build instruction](#build_instruction)
- 4. [Usage](#usage)
- 5. [Result](#result)
- 6. [Example of usage](#example)
- 7. [Authors](#authors)
- 8. [References](#refs)

# 1. About <a name = "about"></a>
Futag is an instrument for automated generating fuzz targets of software libraries. Futag uses clang static analysis to find dependencies of entities (data types, functions, structures, etc.) in the library's source code and generates fuzz targets for functions. The instrument then compiles the fuzz targets with sanitizers and executes them for checking errors. The crashes are collected and saved in a file of SVRES format, the user can import this file to SVACE system for viewing, analyzing. The instrument works on Linux systems.
License: This project is under ["GPL v3 license"](https://llvm.org/docs/DeveloperPolicy.html#new-llvm-project-license-framework)

# 2. Quick start with Dockers <a name = "quick_start"></a>
The Dockers directory contains Dockerfiles of Ubuntu18 and Ubuntu20, which will help you quickly build Futag:
- build-docker: the script for building Docker
- run-docker: the script for running Docker

# 3. Build instruction <a name = "build_instruction"></a>

This instruction will get you a copy of the project and running on a Unix-liked system. FUTAG uses LLVM clang and clang tools as front end to analyze and generate the fuzzing targets.

## 3.1. Prerequisites

Futag is based on [llvm-project](https://llvm.org/). For compiling the project, these packages must be installed on your system:
- [CMake](https://cmake.org/) >=3.13.4 (https://github.com/Kitware/CMake/releases/download/v3.19.3/cmake-3.19.3-Linux-x86_64.sh) -	Makefile/workspace generator
- [GCC](https://gcc.gnu.org/)>=5.1.0	    C/C++ compiler1
- [python](https://www.python.org/) >=3.6	    Automated test suite2
- [zlib](http://zlib.net/) >=1.2.3.4	Compression library3
- [GNU Make](http://savannah.gnu.org/projects/make) 3.79, 3.79.1	Makefile/build processor

Please check [prerequirement](https://llvm.org/docs/GettingStarted.html#requirements) on official website of LLVM for more detail.

## 3.2. Build and install

- Clone the project with submodule llvm-project:
```
~$ git clone --recurse-submodules git@github.com:ispras/Futag.git
```
- Create build folder and copy build.bash script to build folder then change to build folder and run the build.bash script:
```
~/futag$ cp build.bash build
~/futag$ cd build
~/futag/build$ ./build.bash
```
- After all, the instrument will be installed in folder futag 

# 4. Usage <a name="usage"></a>

## 4.1. Prerequisites
You can execute the instrument on other Linux systems (Futag has been tested on Ubuntu 18.04 and Ubuntu 20.04) with these packages installed:
- for Ubuntu 18.04:
```
libncurses5 make gdb binutils libgcc-5-dev
```
- for Ubuntu 20.04:
```
libncurses5 make gdb binutils gcc-multilib g++ 
```
## 4.2. Preparing
- The testing library should be configured with sanitizer and installed in a custom folder. Examples of config script: 
```
~/library-source$ configure --with-openssl --prefix=/home/futag/library-source/local-install CC=/path/to/futag/bin/clang CFLAGS="-fsanitize=address -fprofile-instr-generate -fcoverage-mapping -g -O0" LDFLAGS="-fsanitize=address -fprofile-instr-generate -fcoverage-mapping -g -O0"
~/library-source$ make && make install
```
- or for Cmake:
```
~/library-source$ cmake -G "Unix Makefiles" -DCMAKE_C_FLAGS="-fsanitize=address -fprofile-instr-generate -fcoverage-mapping -g -O0" -DCMAKE_C_COMPILER="/path/to/futag/bin/clang" -DCMAKE_INSTALL_PREFIX=local-install ..
~/library-source$ make && make install
```
- /path/to/futag is the path to folder futag received in the stage [Build instruction](#build_instruction)

## 4.3. Fuzzing
The script "tools/futag-run.py" helps to generate, compile and execute fuzzing targets of the testing library.
- Execute the script "tools/futag-run.py" on the header file that you want to test:
```
~/library-source/local-install$python3 tools/futag-run.py -a "lib" -i ". include include/curl" -o targetscurl  -s "-lgsasl -lpsl -lssl -lcrypto -lssl -lcrypto -lldap -llber -lz" -tt 120 -f 4 -m 8000 include/curl/curl.h
```
- Options of the futag-run.py:
```
$ python3 futag-run.py --help
************************************************
*      ______  __  __  ______  ___     ______  *
*     / ____/ / / / / /_  __/ /   |   / ____/  *
*    / /_    / / / /   / /   / /| |  / / __    *
*   / __/   / /_/ /   / /   / ___ | / /_/ /    *
*  /_/      \____/   /_/   /_/  |_| \____/     *
*                                              *
*     Fuzzing target Automated Generator       *
*             a tool of ISP RAS                *
*                                              *
************************************************
* This script is used for running fuzz targets *
************************************************

usage: futag-run.py [-h] [-p PACKAGE] [-i INCLUDE] [-a STATIC_PATH] [-asan]
                    [-s SYSLIBS] [-so OBJECTS] [-gdb] [-d] [-f FORK]
                    [-to TIMEOUT] [-tt MAX_TOTAL_TIME] [-o OUTPUT]
                    [-m MEMLIMIT] [-k] [-0c] [-0f] [-c]
                    header

[Futag]-- [futag] Script for auto compiling,debugging and gathering result.

positional arguments:
  header                Header file for fuzzing

optional arguments:
  -h, --help            show this help message and exit
  -p PACKAGE, --package PACKAGE
                        path to futag, by default futag is in the same folder
                        of this script
  -i INCLUDE, --include INCLUDE
                        paths for including when compiling
  -a STATIC_PATH, --static_path STATIC_PATH
                        path to folder of installed libraries
  -asan, --futag_asan   Compile with futag ASAN
  -s SYSLIBS, --syslibs SYSLIBS
                        list of system libs for compiling
  -so OBJECTS, --objects OBJECTS
                        list of object files for compiling
  -gdb, --gdb_debug     Option for debugging with gdb
  -d, --debug           Option for viewing debugging info while compiling
  -f FORK, --fork FORK  Fork option for libFuzzer
  -to TIMEOUT, --timeout TIMEOUT
                        Time out for fuzzing
  -tt MAX_TOTAL_TIME, --max_total_time MAX_TOTAL_TIME
                        Max total time out for fuzzing
  -o OUTPUT, --output OUTPUT
                        Folder for generating fuzz-targets
  -m MEMLIMIT, --memlimit MEMLIMIT
                        Memory limit for fuzzing
  -k, --makefile        Option for exporting list of compiling commands to
                        Makefile.futag
  -0c, --nocompiling    Option for fuzzing without compiling
  -0f, --nofuzzing      Option for executing without fuzzing
  -c, --coverage        Option for counting coverage
```
For more detail, you can read the documentation of using Futag at [docs/How to use Futag.pdf](#)

# 5. Result <a name = "result"></a>
The results of testing are presented in 2 types:
- log files in the output folder of futag-run
- file of SVRES format for importing in SVACE system (a system for static analysis of ISP RAS) for viewing.

# 6. Example of usage <a name = "example"></a>
You can run the Dockerfiles for examples, however in the following, we introduce how to run Futag with library CURL manually. 

- Install packages for curl:
```
apt install libssl-dev zlib1g-dev wget libpsl-dev libgsasl7-dev libldap-dev
```

- Download and install curl:
```
~$ wget https://github.com/curl/curl/releases/download/curl-7_79_1/curl7.79.1.tar.gz
~$ tar -xf curl-7.79.1.tar.gz
~$ cd curl-7.79.1/
~/curl-7.79.1$ mkdir build
~/curl-7.79.1$ mkdir build/local-install
~/curl-7.79.1$ cd build
~/curl-7.79.1/build$
~/curl-7.79.1/build$ ../configure --with-openssl --prefix=/home/futag/curl7.79.1/build/local-install CC=/path/to/futag/bin/clang CFLAGS="-fsanitize=address -fprofile-instr-generate -fcoverage-mapping -g -O0" LDFLAGS="-fsanitize=address -g -O0"
~/curl-7.79.1/build$ make && make install
```

- Copy folder futag and python script tools/futag-run to ~/curl-7.79.1/build/local-install and run:
```
~/curl-7.79.1/build/local-install $ python3 /path/to/futag/tools/futag-run.py  -i ". include include/curl" -a "lib" -o targetscurl -s "-lgsasl -lpsl -lssl -lcrypto
-lssl -lcrypto -lldap -llber -lz" -tt 300 -f 4 -m 8000 include/curl/curl.h
```

- All the generated fuzz targets and log files are saved in folder targetscurl.

# 7. Authors <a name = "authors"></a>
- Thien Tran (thientc@ispras.ru)
- Shamil Kurmangaleev (kursh@ispras.ru)

# 8. References <a name = "refs"></a>
- Updating...