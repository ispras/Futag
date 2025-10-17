# Table of Contents

- [Table of Contents](#table-of-contents)
- [1. Description](#1-description)
- [2. Papers and Materials](#2-papers-and-materials)
- [3. Installation](#3-installation)
  - [3.1. Using the Docker container](#31-using-the-docker-container)
  - [3.2. Using a prepackaged release](#32-using-a-prepackaged-release)
  - [3.3. Building and installing from source](#33-building-and-installing-from-source)
    - [3.3.1. Dependencies](#331-dependencies)
    - [3.3.2. Build and install](#332-build-and-install)
- [4. Usage Examples](#4-usage-examples)
    - [4.1. Automatic generation of fuzzing wrappers when usage contexts are absent](#41-automatic-generation-of-fuzzing-wrappers-when-usage-contexts-are-absent)
    - [4.2. Automatic generation of fuzzing wrappers when a consumer program is available](#42-automatic-generation-of-fuzzing-wrappers-when-a-consumer-program-is-available)
  - [5. Authors](#5-authors)
  - [6. Reported Bugs](#6-reported-bugs)
  - [7. Results](#7-results)

# 1. Description
When fuzz-testing libraries, achieving broader coverage requires improving both the quality and the quantity of fuzzing wrappers (fuzz targets). In large software projects and libraries that contain many user-defined functions and data types, manually creating fuzzing wrappers is time-consuming and labor-intensive. This motivates the need for automated approaches not only to generate fuzzing wrappers but also to simplify their execution and the analysis of results, especially under limited-resource conditions.

FUTAG is a tool for automated generation of fuzzing wrappers for software libraries.
FUTAG can generate fuzzing wrappers both when usage contexts for the tested library are absent and when such contexts are available.
FUTAG uses Clang tooling as an external interface to analyze library source code.

The static analyzer implemented in FUTAG performs the following during the build of the target library:
- locate entity definitions (data types, functions, structures, etc.);
- discover dependencies between entities;

The collected information is stored as a knowledge base about the tested library (KB). When usage contexts are not available, the FUTAG generator inspects the KB and creates fuzzing wrappers.

When usage contexts are available, FUTAG searches for function calls, builds dependencies between the discovered calls, and constructs call contexts.

The workflow of FUTAG is illustrated in the following figure:
![](futag-work.png)

This project is built on LLVM with Clang static analysis and is distributed under the "GPL v3" license (see: https://llvm.org/docs/DeveloperPolicy.html#new-llvm-project-license-framework).

# 2. Papers and Materials

If you use FUTAG in your research or when reporting bugs found with FUTAG, please cite the following works:

- Thien, T.C. Enhancing Fuzz Testing Efficiency through Automated Fuzz Target Generation. Program Comput Soft 51, 349–356 (2025). https://doi.org/10.1134/S0361768825700227
- Tran C. T., Kurmangaleev S.: Futag: automated fuzz target generator for testing software libraries. In: 2021 Ivannikov Memorial Workshop (IVMEM), pp. 80–85. IEEE, Nizhny Novgorod (2021). https://doi.org/10.1109/IVMEM53963.2021.00021

Thank you for acknowledging the authors' work when you use FUTAG or report bugs discovered using this tool.


- Research on automatic generation of fuzzing wrappers for library functions, Ivannikov ISPRAS Open Conference 2022

[![Video](https://img.youtube.com/vi/qw_tzzgX04E/hqdefault.jpg)](https://www.youtube.com/watch?v=qw_tzzgX04E&t=28122s)


# 3. Installation
## 3.1. Using the Docker container
You can try building FUTAG using the provided Dockerfiles for Ubuntu: https://github.com/ispras/Futag/tree/main/product-tests/build-test

## 3.2. Using a prepackaged release
- Download the latest release (for example, futag-llvm.2.1.1.tar.xz) from https://github.com/ispras/Futag/releases/tag/2.1.1 and extract it. The tool will be installed to the futag-llvm directory.
- To build AFLplusplus, run the buildAFLplusplus.sh script in futag-llvm:

```bash
  ~/futag-llvm$ ./buildAFLplusplus.sh
```

## 3.3. Building and installing from source

### 3.3.1. Dependencies
These instructions show how to build a copy of the project and run it on a Unix-like system.

FUTAG is based on the LLVM project. To compile the project, the following packages must be installed on your system:

- [CMake](https://cmake.org/) >= 3.13.4 (example: cmake-3.19.3-Linux-x86_64.sh) - build system generator
- [GCC](https://gcc.gnu.org/) >= 7.1.0 - C/C++ compiler
- [Python](https://www.python.org/) >= 3.8 - automated test suite
- [pip](https://pypi.org/project/pip/) >= 22.1.1
- [zlib](http://zlib.net/) >= 1.2.3.4 - compression library
- [GNU Make] - (make) 3.79, 3.79.1 - make/build processor
- [Binutils](https://www.gnu.org/software/binutils/)

For more detailed information about dependencies required to build LLVM, see: https://llvm.org/docs/GettingStarted.html#requirements

On Ubuntu you may also need to install:
- python-is-python3
- gcc-multilib
- binutils-gold binutils-dev

### 3.3.2. Build and install

- Clone the repository:

```bash
  ~$ git clone https://github.com/ispras/Futag
```
- Prepare the "custom-llvm" directory by running the script:

```bash
  ~/Futag/custom-llvm$ ./prepare.sh
```
This script creates the Futag/build directory and copies Futag/custom-llvm/build.sh into it.

- Run the copied build script in "Futag/build":

```bash
  ~/Futag/build$ ./build.sh
```

- After the build the tool will be installed into Futag/futag-llvm

- To build AFLplusplus run buildAFLplusplus.sh in Futag/futag-llvm:

```bash
  ~/Futag/futag-llvm$ ./buildAFLplusplus.sh
```

# 4. Usage Examples
- A workshop on using FUTAG is available in the repository: [workshop/](./workshop/)

- Make sure the futag-<version>.tar.gz package is installed under futag-llvm/python-package/:
```bash
  ~$ pip install -r futag-llvm/python-package/requirements.txt
  ~$ pip install futag-llvm/python-package/futag-2.1.1.tar.gz
```

### 4.1. Automatic generation of fuzzing wrappers when usage contexts are absent
- Run the build, check and analysis when no usage contexts exist:

```python
from futag.preprocessor import *

FUTAG_PATH = "/home/futag/Futag-tests/futag-llvm/"
lib_path = "path/to/library/source/code"
build_test = Builder(
    FUTAG_PATH,
    lib_path,
    clean=True, # remove all folders generated by FUTAG before building
    # intercept=True, # enable compilation with the "intercept" tool to analyze compile_command.json
    # processes=4, # number of build jobs
    # build_ex_params="--with-openssl --with-mhash" # extra params for library build
)
build_test.auto_build()
build_test.analyze()
```

- Generate and compile drivers:

```python
from futag.generator import *

FUTAG_PATH = "/home/futag/Futag-tests/futag-llvm/"
lib_path = "path/to/library/source/code"

generator = Generator(
    FUTAG_PATH, # path to the "futag-llvm" directory
    lib_path, # path to the directory containing the target software source code
    # target_type=AFLPLUSPLUS, 
)

# Generate fuzzing wrappers
generator.gen_targets(
    anonymous=False, # option to generate wrappers for non-public functions
    max_wrappers=10 # limit the number of generated wrappers per function
)
# Compile fuzz drivers
generator.compile_targets(
    4, # number of build jobs
    # keep_failed=True, # keep failed targets
    # extra_include="-DHAVE_CONFIG_H", # extra include flags for building the library
    # extra_dynamiclink="-lz", # system libraries to link
    # flags="-ferror-limit=1", # default: ""
)
```

By default, successfully compiled fuzzing wrappers for target functions are placed in the futag-fuzz-drivers directory, where each target function has its own subdirectory named after the function.

### 4.2. Automatic generation of fuzzing wrappers when a consumer program is available

```python
from futag.preprocessor import *
from futag.generator import * 
from futag.fuzzer import * 

FUTAG_PATH = "/home/futag/Futag/futag-llvm"
library_root = "json-c-json-c-0.16-20220414"
consumer_root = "libstorj-1.0.3"
consumber_builder = ConsumerBuilder(
   FUTAG_PATH, # path to the "futag-llvm" directory
   library_root, # path to the directory with the tested library's source code
   consumer_root, # path to the directory with the consumer application's source code
  #  clean=True,
  #  processes=16,
)
consumber_builder.auto_build()
consumber_builder.analyze()

context_generator = ContextGenerator(
    FUTAG_PATH, 
    library_root, 
)

context_generator.gen_context() # generate fuzzing wrappers for contexts
context_generator.compile_targets( # compile generated fuzzing wrappers
    keep_failed=True,
)
```

If multiple fuzzing wrappers are generated for a function, the target function's subdirectory will contain numbered subdirectories (appended to the function name).
Python package documentation is available at: https://github.com/ispras/Futag/tree/main/src/python/futag-package

More information about using FUTAG is available at: https://github.com/ispras/Futag/blob/main/How-to-work-with-Futag.md

A template for run scripts can be found here: https://github.com/ispras/Futag/blob/main/src/python/template-script.py

A test repository was created at https://github.com/thientc/Futag-tests to test FUTAG on various libraries (json-c, php, FreeImage, etc.). You can try testing using the Docker container at https://github.com/ispras/Futag/tree/main/product-tests/libraries-test.

## 5. Authors

- [Tran Chi Thien](https://github.com/thientc/)
- Shamil Kurmangaleev
- Dmitry Ponomarev
- Andrey Kuznetsov
- Theodor Arsenij Larionov-Trichkin


## 6. Reported Bugs

| **Library** | **Version** |       **Function**      |                **Bug type**               |                         **Date of report**                        | **Date of patch** |
|:-----------:|:-----------:|:-----------------------:|:-----------------------------------------:|:-----------------------------------------------------------------:|:-----------------:|
| libpng      | 1.6.37      | png_convert_from_time_t | AddressSanitizer:DEADLYSIGNAL             | [Feb 8, 2021](https://github.com/glennrp/libpng/issues/362)       | Sep 13, 2022      |
| tinyxml2    | 9.0.0       | ErrorIDToName           | AddressSanitizer: global-buffer-overflow  | [Nov 2, 2022](https://github.com/leethomason/tinyxml2/issues/923) | Nov 12, 2022      |
| pugixml     | 1.13        | default_allocate        | AddressSanitizer: allocation-size-too-big | [Apr 11, 2023](https://github.com/zeux/pugixml/issues/560)        | Apr 15, 2023      |
|             |             |                         |                                           |                                                                   |                   |

## 7. Results

| **Library** | **Generation time (s)** | **Number of fuzzing wrappers** | **Compilation time (s)** | **Lines of code** |
|:---:|---:|:---:|:---:|:---:|
| lib json-c | 180 | **3111** | 612 | 280,019 |
| libpostgres | 105 | **749** | 29 | 84,387 |
| curl | 4,210 | **152** | 21 | 9,617 |
| openssl | 2,172 | **269** | 255 | 19,458 |
| pugixml | 55 | **61** | 58 | 2,815 |
| libopus | 75 | **422** | 7 | 12,606 |