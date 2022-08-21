# Python package of Futag
```bash
    **************************************************
    **      ______  __  __  ______  ___     ______  **
    **     / ____/ / / / / /_  __/ /   |   / ____/  **
    **    / /_    / / / /   / /   / /| |  / / __    **
    **   / __/   / /_/ /   / /   / ___ | / /_/ /    **
    **  /_/      \____/   /_/   /_/  |_| \____/     **
    **                                              **
    **     Fuzzing target Automated Generator       **
    **             a tool of ISP RAS                **
    **************************************************
    ** This package is for building, generating,    **
    **  compiling fuzz-drivers of library functions **
    **************************************************
```
This python package is for building library, generating and compiling fuzz-drivers of functions.
* Package url: https://github.com/ispras/Futag/tree/main/src/python/futag-package
* Bug Tracker = https://github.com/ispras/Futag/issues
## 1. Install

```bash 
pip install dist/futag-1.0.tar.gz
```

## 2. Preprocessor
* Prerequisite: You must have [llvm-package with Futag checker](https://github.com/ispras/Futag/blob/main/README.en.md#22-build-and-install) to analyze your library.

The preprocessor module tries to configure and build your library with configure file or cmake, you should specify path to futag-llvm-package and path. The library then will be built with address sanitizer and Futag-checker. The class Builder of this module has 4 method:
- auto-build: automatically builds your library
- build_configure(): builds your library with configure file
- build_cmake(): builds your library with cmake
- analyze(): analyzes the result of Futag-checker. This method will generate json file futag-analysis-result.json.

Example:
```python
from futag.preprocessor import *

json0_13 = Builder("../../futag-llvm-package", "json-c-json-c-0.13.1-20180305")
json0_13.auto_build()
json0_13.analyze()
```
or
```python
from futag.preprocessor import *

json0_13 = Builder("../../futag-llvm-package", "json-c-json-c-0.13.1-20180305")
json0_13.build_configure()
json0_13.analyze()
```

For more parameters of Builder please refer to docstring of this class.
```bash
    class Builder(builtins.object)
    |  Builder(futag_llvm_package: str, library_root: str, clean: bool = False, build_path: str = 'futag-build', install_path: str = 'futag-install', analysis_path: str = 'futag-analysis', processes: int = 16, build_ex_params='')
    |  
    |  Futag Builder Class
    |  
    |  Methods defined here:
    |  
    |  __init__(self, futag_llvm_package: str, library_root: str, clean: bool = False, build_path: str = 'futag-build', install_path: str = 'futag-install', analysis_path: str = 'futag-analysis', processes: int = 16, build_ex_params='')
    |      Parameters
    |      ----------
    |      futag_llvm_package: str
    |          (*required) path to the futag llvm package (with binaries, scripts, etc)
    |      library_root: str
    |          (*required) path to the library root
    |      clean: bool
    |          Option for deleting futag folders if they are exist (futag-build, futag-install, futag-analysis)
    |      build_path: str
    |          path to the build directory. This directory will be deleted and create again if clean set to True.
    |      install_path: str
    |          path to the install directory. Be careful, this directory will be deleted and create again if clean set to True.
    |      analysis_path: str
    |          path for saving report of analysis. This directory will be deleted and create again if clean set to True.
    |      processes: int
    |          number of processes while building.
    |      build_ex_params: str
    |          extra params for building, for example "--with-openssl" for building curl
    |  
    |  analyze(self)
    |      This function reads analysis result of Futag checker
    |  
    |  auto_build(self) -> int
    |      This function tries to automatically build your library.
    |      It finds in your library source code whether configure file or CMakeList.txt file exists.
    |  
    |  build_cmake(self) -> int
    |      This function tries to build your library with cmake.
    |  
    |  build_configure(self) -> int
    |      This function tries to build your library with configure.
    |  
    |  ----------------------------------------------------------------------

```

## 3. Generator
The module Generator is for generating, compiling fuzz-drivers. You should specify path to analysis result (file futag-analysis-result.json), path to futag-llvm-package and the path to library. For more detail please refer to docstring of module.

Example:
```python
from futag.generator import * 
generator = Generator(
    "json-c-json-c-0.13.1-20180305/futag-analysis/futag-analysis-result.json", 
    "../futag-llvm-package",
    "json-c-json-c-0.13.1-20180305" 
  )
generator.gen_targets()
generator.compile_targets(True, 16) #number of processes while compiling
```
The fuzz-drivers of libjson will be generated in futag-fuzz-drivers inside the library root.

```bash
    class Generator(builtins.object)
     |  Generator(json_file: str, futag_llvm_package: str, library_root: str, output_path='futag-fuzz-drivers', build_path='futag-build', install_path='futag-install')
     |  
     |  Futag Generator
     |  
     |  Methods defined here:
     |  
     |  __init__(self, json_file: str, futag_llvm_package: str, library_root: str, output_path='futag-fuzz-drivers', build_path='futag-build', install_path='futag-install')
     |      Parameters
     |      ----------
     |      json_file: str
     |          path to the futag-analysis-result.json file
     |      futag_llvm_package: str
     |          path to the futag llvm package (with binaries, scripts, etc)
     |      library_root: str
     |          path to the library root
     |      output_path : str
     |          where to save fuzz-drivers, default to "futag-fuzz-drivers".
     |      build_path: str
     |          path to the build directory, default to "futag-build".
     |      install_path: str
     |          path to the install directory, default to "futag-install".
     |
     |
     |  compile_targets(self, makefile: bool = True, workers: int = 4)
     |      Parameters
     |      ----------
     |      makefile: bool
     |          option for generating makefile (Makefile.futag)
     |      workers: int
     |          number of processes for compiling
     |  ----------------------------------------------------------------------
```

## 4. Fuzzer

The class Fuzzer helps automatically fuzz targets

```python
from futag.fuzzer import *
f = Fuzzer("/Futag/futag-llvm-package", 
"json-c-json-c-0.13.1-20180305/futag-fuzz-drivers")
f.fuzz()
```

```bash
class Fuzzer(builtins.object)
 |  Fuzzer(futag_llvm_package: str, fuzz_driver_path: str = 'futag-fuzz-drivers', leak: bool = False, debug: bool = False, svres: bool = False, gdb: bool = False, fork: int = 1, timeout: int = 10, totaltime: int = 300, memlimit: int = 2048, coverage: bool = False, introspect: bool = False)
 |  
 |  Futag Fuzzer
 |  
 |  Methods defined here:
 |  
 |  __init__(self, futag_llvm_package: str, fuzz_driver_path: str = 'futag-fuzz-drivers', debug: bool = False, gdb: bool = False, svres: bool = False, fork: int = 1, totaltime: int = 300, timeout: int = 10, memlimit: int = 2048, coverage: bool = False, leak: bool = False, introspect: bool = False)
 |      Parameters
 |      ----------
 |      futag_llvm_package: str
 |          path to the futag llvm package (with binaries, scripts, etc)
 |      fuzz_driver_path: str
 |          location of fuzz-drivers, default "futag-fuzz-drivers"
 |      debug: bool = False
 |          print debug infomation while fuzzing, default False
 |      gdb: bool = False
 |          debug crashes with GDB, default False
 |      svres: bool = False
 |          generate svres file for Svace (if you have Svace), default False
 |      fork: int = 1
 |          fork mode of libFuzzer (https://llvm.org/docs/LibFuzzer.html#fork-mode), default 1 - no fork mode
 |      totaltime: int = 300
 |          total time of fuzzing one fuzz-driver, default 300 seconds
 |      timeout: int = 10
 |          if an fuzz-drive takes longer than this timeout, the process is treated as a failure case, default 10 seconds
 |      memlimit: int = 2048
 |          option for rss_limit_mb of libFuzzer - Memory usage limit in Mb, default 2048 Mb, Use 0 to disable the limit.
 |      coverage: bool = False
 |          option for showing coverage of fuzzing, default False.
 |      leak: bool = False
 |          detecting memory leak, default False
 |      introspect: bool = False
 |          option for integrate with fuzz-introspector (to be add soon).
 |  

```