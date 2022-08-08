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

- Currently Futag supports libraries in C language.

## 2. Build instruction

This instruction will get you a copy of the project and running on a Unix-liked system. FUTAG uses LLVM clang and clang tools as front end to analyze and generate the fuzzing targets.

### 2.1. Prerequisites

Futag is based on [llvm-project](https://llvm.org/). For compiling the project, these packages must be installed on your system:

- [CMake](https://cmake.org/) >=3.13.4 [cmake-3.19.3-Linux-x86_64.sh](https://github.com/Kitware/CMake/releases/download/v3.19.3/cmake-3.19.3-Linux-x86_64.sh) - Makefile/workspace generator
- [GCC](https://gcc.gnu.org/)>=5.1.0 C/C++ compiler
- [python](https://www.python.org/) >=3.6 
- [pip](https://pypi.org/project/pip/)
- [zlib](http://zlib.net/) >=1.2.3.4 Compression library
- [GNU Make](http://savannah.gnu.org/projects/make) 3.79, 3.79.1 Makefile/build processor

Please check [prerequirement](https://llvm.org/docs/GettingStarted.html#requirements) on official website of LLVM for more detail.

### 2.2. Build and install

#### Install custom LLVM package

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

- After this stage, the instrument will be installed in folder Futag/futag-llvm-package

#### Install python package of Futag:

 ```bash
    ~$ pip install Futag/src/python/futag-package/dist/futag-1.1.tar.gz
  ```

## 3. Example usage

Example of execution Futag

- Analyze the library:

```python
# package futag must be already installed
from futag.preprocessor import *

json0_13 = Builder(
    "Futag/futag-llvm-package/", # path to the futag-llvm-package
    "json-c-json-c-0.13.1-20180305" # library root
)
json0_13.auto_build()
json0_13.analyze()
```

- Generate and compile fuzz-drivers

```python
# package futag must be already installed
from futag.generator import *

g = Generator(
"json-c-json-c-0.13.1-20180305/futag-analysis/futag-analysis-result.json", # path to result file of analysis
"Futag/futag-llvm-package/", # path to the futag-llvm-package
"json-c-json-c-0.13.1-20180305" # library root
)

# Generate fuzz drivers
g.gen_targets()

# Compile fuzz drivers
g.compile_targets()
```

- Fuzz generated targets:

```python
from futag.fuzzer import *
f = Fuzzer("/Futag/futag-llvm-package", 
"json-c-json-c-0.13.1-20180305/futag-fuzz-drivers")
f.fuzz()
```

For more detail please read [the document](https://github.com/ispras/Futag/tree/main/src/python/futag-package) of package

## 4. Authors

- Thien Tran (thientc@ispras.ru)
- Shamil Kurmangaleev (kursh@ispras.ru)
- Theodor Arsenij Larionov-Trichkin (tlarionov@ispras.ru)

## 5. References

- C. T. Tran and S. Kurmangaleev, ["Futag: Automated fuzz target generator for testing software libraries"](https://ieeexplore.ieee.org/document/9693749) 2021 Ivannikov Memorial Workshop (IVMEM), 2021, pp. 80-85, doi: 10.1109/IVMEM53963.2021.00021.