# Table of Contents

- [Table of Contents](#table-of-contents)
  - [1. About](#1-about)
  - [2. Installation](#2-installation)
  - [3. Usage](#3-usage)
  - [4. Authors](#4-authors)
  - [5. References](#5-references)
  - [6. Found bugs](#6-found-bugs)

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
- automatically generating fuzzing-targets for functions of libraries in C/C++ languages.
Additionally, Futag provides the ability to test compiled targets.

## 2. Installation
### 2.1. Using a docker container
You can try to build Futag with pre-built [Docker files](https://github.com/ispras/Futag/tree/main/product-tests/build-test) for Ubuntu OS.

### 2.2. Using a prepackaged package
Download the latest [futag-llvm.2.0.1.tar.xz](https://github.com/ispras/Futag/releases/tag/2.0.0) and unzip

### 2.3. Building and installing from source

#### 2.3.1. Dependencies
This instruction allows you to build a copy of the project and run it on a Unix-like system.

Futag is based on [llvm-project](https://llvm.org/). For compiling the project, these packages must be installed on your system:

- [CMake](https://cmake.org/) >=3.13.4 [cmake-3.19.3-Linux-x86_64.sh](https://github.com/Kitware/CMake/releases/download/v3.19.3/cmake-3.19.3-Linux-x86_64.sh) - Makefile/workspace generator
- [GCC](https://gcc.gnu.org/)>=5.1.0 C/C++ compiler
- [python](https://www.python.org/) >=3.6 
- [pip](https://pypi.org/project/pip/)
- [zlib](http://zlib.net/) >=1.2.3.4 Compression library
- [GNU Make](http://savannah.gnu.org/projects/make) 3.79, 3.79.1 Makefile/build processor

Please check [prerequirement](https://llvm.org/docs/GettingStarted.html#requirements) on official website of LLVM for more detail.

You also need to create a symbolic link "python" to "python3" if such a link does not exist on your system. On an Ubuntu system, this can be done by installing the python-is-python3 package.

#### 2.3.1. Building and installing

- Clone the project:

```bash
  ~$ git clone https://github.com/ispras/Futag
```
- Prepare the "custom-llvm" directory by running the script:
```bash
  ~/Futag/custom-llvm$ ./prepare.sh
```
This script creates the Futag/build directory and copies the Futag/custom-llvm/build.sh script into it.

Run the copied script in "Futag/build":

```bash
  ~/Futag/build$ ./build.sh
```

- As a result, the tool will be installed in the Futag/futag-llvm directory.

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

### 3.1. Traditional Static Analysis-Based Generation

- Generate and compile fuzz-drivers

```python
# package futag must be already installed
from futag.generator import *

g = Generator(
    "futag-llvm/", # path to the futag-llvm
    "path/to/library/source/code" # library root
    # target_type = LIBFUZZER, # or AFLPLUSPLUS
)
g.gen_targets(
  anonymous=False # Option for generating fuzzing-wrapper of private functions
)
g.compile_targets(
  8, # Compile fuzz drivers with 8 processes
  # keep_failed=True, # keep uncompiled targets
  # extra_include="-DHAVE_CONFIG_H", # extra included paths
  # extra_dynamiclink="-lz", # extra system linked libraries
  # flags="-ferror-limit=1", # flags for compiling, default to ""
)
```

### 3.2. LLM-Based Generation (NEW - Similar to oss-fuzz-gen)

**Futag now supports LLM-based fuzzing wrapper generation, similar to [oss-fuzz-gen](https://github.com/google/oss-fuzz-gen) project.**

#### Cloud LLMs (OpenAI, Anthropic)

Install additional dependencies for cloud LLMs:

```bash
pip install openai anthropic
```

Example using OpenAI GPT-4:

```python
from futag.preprocessor import *
from futag.generator import *

FUTAG_PATH = "futag-llvm/"
lib_path = "path/to/library/source/code"

# Build and analyze library
builder = Builder(FUTAG_PATH, lib_path)
builder.auto_build()
builder.analyze()

# Generate fuzzing wrappers with LLM
generator = Generator(FUTAG_PATH, lib_path)
stats = generator.gen_targets_with_llm(
    llm_provider="openai",      # Provider: 'openai', 'anthropic'
    llm_model="gpt-4",           # Model: 'gpt-4', 'gpt-3.5-turbo', etc.
    max_functions=10,            # Maximum number of functions
    temperature=0.7              # Generation temperature (0.0-1.0)
)

print(f"Generated {stats['successful']} fuzzing harnesses")
```

#### Local LLMs (Ollama, LM Studio) - **FREE and OFFLINE!**

**New in Futag:** Now you can use local LLMs for fuzzing harness generation completely free and without internet connection!

For local LLMs:

```bash
# Install dependencies
pip install requests

# Install Ollama (https://ollama.ai/download)
# Start the server
ollama serve

# Pull a code generation model
ollama pull codellama:13b
```

Example using Ollama:

```python
from futag.preprocessor import *
from futag.generator import *

FUTAG_PATH = "futag-llvm/"
lib_path = "path/to/library/source/code"

# Build and analyze library
builder = Builder(FUTAG_PATH, lib_path)
builder.auto_build()
builder.analyze()

# Generate fuzzing wrappers with local LLM
generator = Generator(FUTAG_PATH, lib_path)
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",           # Local provider
    llm_model="codellama:13b",       # Or: deepseek-coder:6.7b, mistral
    max_functions=10,
    temperature=0.2                  # Lower temperature for code
)

print(f"Generated {stats['successful']} fuzzing harnesses")
```

**Benefits of Local LLMs:**
- ✅ Completely free (no API costs)
- ✅ Complete privacy (data stays on your machine)
- ✅ Works offline (after model download)
- ✅ Unlimited generations
- ✅ Good quality with proper models (CodeLlama, DeepSeek Coder)

**Recommended models:**
- `codellama:13b` - best for code generation
- `deepseek-coder:6.7b` - code specialist
- `mistral` - general purpose model

You can also combine traditional and LLM-based generation:

```python
# Traditional generation
generator.gen_targets(anonymous=False, max_wrappers=10)

# Supplement with LLM generation (local or cloud)
generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="codellama:13b",
    max_functions=5
)

# Compile all generated wrappers
generator.compile_targets(workers=4, keep_failed=True)
```

**Learn more about LLM-based generation:**
- [LLM Generation Documentation (English)](docs/LLM-GENERATION.md)
- [Local LLM Support Guide](docs/LOCAL-LLM-SUPPORT.md)
- [Cloud LLM Example](src/python/example-llm-generation.py)
- [Local LLM Example](src/python/example-local-llm-generation.py)
By default, successfully compiled fuzz-drivers for target functions are located in the futag-fuzz-drivers directory, where each target function is in its own subdirectory, the name of which matches the name of the target function.
If several fuzz-drivers have been generated for a function, corresponding directories are created in the subdirectory of the target function, where a serial number is added to the name of the target function.

Documentation Futag Python-package follows by this [link](https://github.com/ispras/Futag/tree/main/src/python/futag-package)

Details of working with Futag can be read [here](https://github.com/ispras/Futag/blob/main/How-to-work-with-Futag.md)

The example script can be viewed [here](https://github.com/ispras/Futag/blob/main/src/python/template-script.py)

[Testing repository](https://github.com/thientc/Futag-tests) has been created to test Futag for libraries (json-c, php, FreeImage, etc.), you can try with [Docker container]( https://github.com/ispras/Futag/tree/main/product-tests/libraries-test).

## 4. Authors

- [Tran Chi Thien](https://github.com/thientc/) (thientc@ispras.ru)
- Shamil Kurmangaleev (kursh@ispras.ru)
- Theodor Arsenij Larionov-Trichkin (tlarionov@ispras.ru)

## 5. References

- C. T. Tran and S. Kurmangaleev, ["Futag: Automated fuzz target generator for testing software libraries"](https://ieeexplore.ieee.org/document/9693749) 2021 Ivannikov Memorial Workshop (IVMEM), 2021, pp. 80-85, doi: 10.1109/IVMEM53963.2021.00021.

- Research on automatic generation of fuzz-target for software library functions, Ivannikov ISP RAS Open Conference 2022

[![Видео](https://img.youtube.com/vi/qw_tzzgX04E/hqdefault.jpg)](https://www.youtube.com/watch?v=qw_tzzgX04E&t=28122s) 

## 6. Found bugs

- Crash in function [png_convert_from_time_t](https://github.com/glennrp/libpng/issues/362) of [libpng version 1.6.37](https://github.com/glennrp/libpng) (confirmed)

- Global-buffer-overflow in function [ErrorIDToName](https://github.com/leethomason/tinyxml2/issues/923) of tinyxml2 version 9.0.0