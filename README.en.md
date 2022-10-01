# Table of Contents

- [Table of Contents](#table-of-contents)
  - [1. About](#1-about)
  - [2. Install](#2-install)
  - [3. Usage](#3-usage)
  - [4. Build from source code](#4-build-from-source-code)
  - [5. Authors](#5-authors)
  - [6. References](#6-references)
  - [7. Found bugs](#7-found-bugs)

## 1. About

Futag is an automated instrument to generate fuzz targets for software libraries.
Unlike the standalone program, software library may not contain an entry point so that generating fuzz target for it remains a challenge.
FUTAG uses LLVM clang and clang tools as front end to analyze and generate the fuzzing targets.
Futag uses static analysis to find:
- Entities dependencies (data types, functions, structures, etc.) in the source code of target library.
- Library usage contexts.
The information then is used for generating fuzz targets.

This project is based on llvm-project with Clang statistic analysis, LLVM lto and is distributed under ["GPL v3 license"](https://llvm.org/docs/DeveloperPolicy.html#new-llvm-project-license-framework)

Currently Futag supports:
- automatically compiling libraries with Makefile, cmake and configure;
- automatically generating fuzzing-targets for libraries in C language.
- automatically generating fuzzing-targets for global functions of libraries in C language.
Additionally, Futag provides the ability to test compiled targets.

## 2. Install

This instruction will get you a copy of the project and running on a Unix-liked system. 

### Prerequisites

Futag is based on [llvm-project](https://llvm.org/). For compiling the project, these packages must be installed on your system:

- [CMake](https://cmake.org/) >=3.13.4 [cmake-3.19.3-Linux-x86_64.sh](https://github.com/Kitware/CMake/releases/download/v3.19.3/cmake-3.19.3-Linux-x86_64.sh) - Makefile/workspace generator
- [GCC](https://gcc.gnu.org/)>=5.1.0 C/C++ compiler
- [python](https://www.python.org/) >=3.6 
- [pip](https://pypi.org/project/pip/)
- [zlib](http://zlib.net/) >=1.2.3.4 Compression library
- [GNU Make](http://savannah.gnu.org/projects/make) 3.79, 3.79.1 Makefile/build processor

Please check [prerequirement](https://llvm.org/docs/GettingStarted.html#requirements) on official website of LLVM for more detail.

### Install

- Download release package and extract it: [futag-llvm.latest.tar.gz](https://github.com/ispras/Futag/releases/tag/latest)

- Install requirements: 
```bash
  ~$ pip install -r futag-llvm/python-package/requirements.txt
```
- Install Futag python package from the extracted package futag-llvm/python-package/futag-1.1.tar.gz:

```bash
  ~$ pip install futag-llvm/python-package/futag-1.1.tar.gz
```

## 3. Usage

- Analyze the library:

```python
# package futag must be already installed
from futag.preprocessor import *

testing_lib = Builder(
    "futag-llvm/", # path to the futag-llvm
    "path/to/library/source/code" # library root
)
testing_lib.auto_build()
testing_lib.analyze()
```

- Generate and compile fuzz-drivers

```python
# package futag must be already installed
from futag.generator import *

g = Generator(
"futag-llvm/", # path to the futag-llvm
"path/to/library/source/code" # library root
)
g.gen_targets() # Generate fuzz drivers
g.compile_targets() # Compile fuzz drivers
```
By default, successfully compiled fuzz-drivers for target functions are located in the futag-fuzz-drivers directory, where each target function is in its own subdirectory, the name of which matches the name of the target function.
If several fuzz-drivers have been generated for a function, corresponding directories are created in the subdirectory of the target function, where a serial number is added to the name of the target function.

Documentation Futag Python-package follows by this [link](https://github.com/ispras/Futag/tree/main/src/python/futag-package)

Details of working with Futag can be read [here](https://github.com/ispras/Futag/blob/main/How-to-work-with-Futag.md)

The example script can be viewed [here](https://github.com/ispras/Futag/blob/main/src/python/template-script.py)

[Testing repository](https://github.com/thientc/Futag-tests) has been created to test Futag for libraries (json-c, php, FreeImage, etc.), you can try with [Docker container]( https://github.com/ispras/Futag/tree/main/product-tests/libraries-test).

## 4. Build from source code

- Clone the project:

```bash
  ~$ git clone https://github.com/ispras/Futag
```
- Prepare directory "custom-llvm" by running script:
```bash
  ~/Futag/custom-llvm$ ./prepare.sh
```
This script creates directory Futag/build and copies script Futag/custom-llvm/build.sh there

- Run the build.sh script inside Futag/build:
```bash
  ~/Futag/build$ ./build.sh
```

After this stage, the instrument will be built and installed in folder Futag/futag-llvm

You can try building Futag with ready [Dockerfiles](https://github.com/ispras/Futag/tree/main/product-tests/build-test) for different versions of Ubuntu OS.

## 5. Authors

- [Tran Chi Thien](https://github.com/thientc/) (thientc@ispras.ru)
- Shamil Kurmangaleev (kursh@ispras.ru)
- Theodor Arsenij Larionov-Trichkin (tlarionov@ispras.ru)

## 6. References

- C. T. Tran and S. Kurmangaleev, ["Futag: Automated fuzz target generator for testing software libraries"](https://ieeexplore.ieee.org/document/9693749) 2021 Ivannikov Memorial Workshop (IVMEM), 2021, pp. 80-85, doi: 10.1109/IVMEM53963.2021.00021.

## 7. Found bugs

- Crash in function [png_convert_from_time_t](https://github.com/glennrp/libpng/issues/362) of [libpng version 1.6.37](https://github.com/glennrp/libpng) (confirmed)