
# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [3.0.1] - 2025

### Major Refactoring
- Extracted `BaseGenerator` ABC from 5 duplicated generator classes (12,924 → 4,767 lines)
- Created `GeneratorState` dataclass replacing 13 mutable instance variables
- Extracted `BaseFuzzer` from duplicated Fuzzer/NatchFuzzer (1,602 → 891 lines)
- Moved `ContextGenerator` and `NatchGenerator` to separate modules
- `FuzzDataProviderGenerator` reduced from 2,715 to 222 lines
- `BlobStamperGenerator` reduced from 2,693 to 37 lines

### New Features
- Custom exception hierarchy (`futag.exceptions`: FutagError, InvalidPathError, etc.)
- Python `logging` module integration (replaces print statements)
- `GeneratorState.save()`/`restore_from()` for clean recursive backtracking
- GitHub Actions CI (python-tests.yml, syntax-check.yml)

### Bug Fixes
- Fixed null-pointer dereference in FutagConsumerAnalyzer (cfg->size() before null check)
- Fixed memory leak in FutagConsumerAnalyzer (new int() instead of new int[])
- Fixed `param_list` duplication bug in `__save_old_values`
- Fixed 14+ file handle leaks (bare open() → with statements)
- Fixed `_build_ovearall_coverage` typo → `_build_overall_coverage`
- Replaced bubble sort in `sort_callexprs` with `sorted()`

### Documentation
- Created docs/architecture.md, docs/generators.md, docs/checkers.md, docs/python-api.md
- Created CONTRIBUTING.md
- Added comprehensive docstrings and return type hints to all methods
- Added GPL v3 license headers to all Python source files
- Translated template-script.py comments from Russian to English

### C++ Checker Improvements
- Added `MAX_CFG_BLOCKS` and `REPORT_FILENAME_RAND_LEN` constants
- Changed `SmallString<0>` to `SmallString<256>`
- Added Doxygen comments to all checker methods
- Synchronized base files with LLVM 18 variants

## 20250824
- Add support for Fuzzed Data Provider

## 20230807
- Optimize ConsumerBuilder
- Add example for context-generation https://github.com/thientc/Futag-tests/tree/main/json-c-contexts

## 20230711
- Support generation fuzz driver for Natch data: https://github.com/thientc/Futag-tests/tree/main/Natch

## 20230522
- Fix error in generator
- Add generation for pugi::char_t *&

## 20230417
- Add generation for anonymous function
- Fix error in Builder

## 20230320
- Support for context generation

## 20230305
- Fix error python in Builder
- Fix error python in Generator for wchar_t string

## 20230214
- Add is_simple for 4consummer_analysis_db
- Add CFG and DFC analysis
- Add Fuzzer extra params support

## 20221220
- Fix errors while compiling AFL++, return coverage parameters
- Fix Readme
- change LLVM_ENABLE_ZLIB to ON

## 20221107
- And generation for anonymous functions
- Reformat Python classes
- Fix included paths of compiling command

## 20221018
- Add support for C++, generate for constructors and for method of class, which has default constructors
- Tested on FreeImage and Pugixml

## 20221012
- Add support for AFLplusplus
- Add possibility of building LLVM with different version (12, 13, 14)
- Add analysis for classes, structs, unions...
- Add compilition database of building
- Add analysis of headers

## 20220921
- Add support for Makefile
- Generation for global function of C++ libraries
- Add testing repository: https://github.com/thientc/Futag-tests

## 20220911
- Add support for fuzz-introspector
- Migrate to llvm-14.0.6

## 20220821
- Fix bug in generator
- Add release package
- Fix document

## 20220811
- Fix bug in generator
- Add pre release package
- Fix document

## 20220808
- Fix bug in generator
- Fix for svace analysing
- add first version of fuzzer and result of Fuzzing for Svace

## 20220801
- Add multi-processing support for compiling
- TODO: Check analysis result befor generating fuzz-driver

## 20220727
- Add custom-llvm: download and build llvm, clang, compiler-rt
- Fix document

## 20220716
- Add modules preprocessor to Futag python-package
- Fix README of Futag python-package
