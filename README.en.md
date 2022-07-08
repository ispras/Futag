# Table of Contents

- [Table of Contents](#table-of-contents)
  - [1. About](#1-about)
  - [2. Build instruction](#2-build-instruction)
    - [2.1. Prerequisites](#21-prerequisites)
    - [2.2. Build and install](#22-build-and-install)
  - [3. Example usage](#3-example-usage)
  - [4. Authors](#4-authors)
  - [5. References](#5-references)

## 1. About

Futag is an automated instrument to generate fuzz targets for software libraries.
Unlike the standalone program, software library may not contain an entry point so that generating fuzz target for it remains a challenge.
Futag uses static analysis to find:

- Entities dependencies (data types, functions, structures, etc.) in the source code of target library.
- Library usage contexts.
The information then is used for generating fuzz targets.

This project is based on llvm-project with Clang statistic analysis, LLVM lto and is distributed under ["GPL v3 license"](https://llvm.org/docs/DeveloperPolicy.html#new-llvm-project-license-framework)

## 2. Build instruction

This instruction will get you a copy of the project and running on a Unix-liked system. FUTAG uses LLVM clang and clang tools as front end to analyze and generate the fuzzing targets.

### 2.1. Prerequisites

Futag is based on [llvm-project](https://llvm.org/). For compiling the project, these packages must be installed on your system:

- [CMake](https://cmake.org/) >=3.13.4 [cmake-3.19.3-Linux-x86_64.sh](https://github.com/Kitware/CMake/releases/download/v3.19.3/cmake-3.19.3-Linux-x86_64.sh) - Makefile/workspace generator
- [GCC](https://gcc.gnu.org/)>=5.1.0 C/C++ compiler1
- [python](https://www.python.org/) >=3.6 Automated test suite2
- [zlib](http://zlib.net/) >=1.2.3.4 Compression library3
- [GNU Make](http://savannah.gnu.org/projects/make) 3.79, 3.79.1 Makefile/build processor

Please check [prerequirement](https://llvm.org/docs/GettingStarted.html#requirements) on official website of LLVM for more detail.

### 2.2. Build and install

- Clone the project with submodule llvm-project:

  ```bash
  ~$ git clone --recurse-submodules https://github.com/ispras/Futag
  ```

- Create build folder and copy build.sh script to build folder then change to build folder and run the build.sh script:

  ```bash
  ~/futag$ cp build.sh build && cd build
  ~/futag/build$ ./build.sh
  ```

- After this stage, the instrument will be installed in folder futag-package

- Install python package of Futag:

 ```bash
  ~$ pip install /path/to/python/futag-package/dist/futag-0.1.tar.gz
  ```

## 3. Example usage

Execute futag for test/c_examples/multifile_project

- Run checker

  ```bash
  <path to futag package>/bin/scan-build -analyzer-config futag.FutagFunctionAnalyzer:report_dir=`pwd`/futag-function-analyzer-reports -enable-checker futag make -j 16
  ```

- Compile to a static library (for more info check corresponding Makefile)

  ```bash
  EXTRA_C_FLAGS=-fsanitize=fuzzer-no-link make archive -j16 
  ```

- Merge results

  ```bash
  cd futag-function-analyzer-reports
  python3 <path to futag package>/tools/analyzer/analypar.py .
  ```

- Generate drivers and compile them

  ```python
  # package futag must be already installed

  from futag.generator import *

  g = Generator(
    "fuzz-drivers", 
    "/path/to/futag-analysis-result.json", 
    "/path/to/futag/package/", # path to the futag-package
    "/path/to/library/multifile_project/" # library root
  )

  # Genearate fuzz drivers
  g.gen_targets()

  # Compile fuzz drivers
  g.compile_targets()
  ```

- You can find successfully compiled targets in the fuzz-drivers directory. Each driver is located inside its subfolder.

Execute futag for json-c

- Build library

  ```bash
  cd json-c-sources
  mkdir build && cd build
  CC=<path-to-futag-package>/bin/clang ../configure --prefix=`pwd`/install CFLAGS="-fsanitize=fuzzer-no-link -Wno-error=implicit-const-int-float-conversion"
  make -j16 && make install
  ```

  After this step you can find compiled version of the library here: `<path-to-json-c-sources>/build/install/lib/libjson-c.a`

- Cleanup and configuration

  ```bash
  make clean
  ../configure --prefix=`pwd`/install
  ```

- Run checker

  ```bash
  <path-to-futag-package>/bin/scan-build -analyzer-config futag.FutagFunctionAnalyzer:report_dir=`pwd`/futag-result -enable-checker futag make -j 16
  ```

- Merge results

  ```bash
  cd futag-result
  python3 <path to futag package>/tools/analyzer/analypar.py .
  ```

- Generate drivers and compile them

  ```python
  # package futag must be already installed

  from futag.generator import *

  g = Generator(
    "fuzz-drivers", 
    "/path/to/futag-analysis-result.json", 
    "/path/to/futag/package/", # path to the futag-package
    "/path/to/json-c-root/" # library root
  )

  # Genearate fuzz drivers
  g.gen_targets()

  # Compile fuzz drivers
  g.compile_targets()
  ```

## 4. Authors

- Thien Tran (thientc@ispras.ru)
- Shamil Kurmangaleev (kursh@ispras.ru)
- Theodor Arsenij Larionov-Trichkin (tlarionov@ispras.ru)

## 5. References

- C. T. Tran and S. Kurmangaleev, ["Futag: Automated fuzz target generator for testing software libraries"](https://ieeexplore.ieee.org/document/9693749) 2021 Ivannikov Memorial Workshop (IVMEM), 2021, pp. 80-85, doi: 10.1109/IVMEM53963.2021.00021.