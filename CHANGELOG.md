
# Change Log
All notable changes to this project will be documented in this file.
 
The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## 20220716
- Add modules preprocessor to Futag python-package
- Fix README of Futag python-package

## 20220727
- Add custom-llvm: download and build llvm, clang, compiler-rt
- Fix document

## 20220801
- Add multi-processing support for compiling
- TODO: Check analysis result befor generating fuzz-driver

## 20220808
- Fix bug in generator
- Fix for svace analysing
- add first version of fuzzer and result of Fuzzing for Svace

## 20220811
- Fix bug in generator
- Add pre release package
- Fix document

## 20220821
- Fix bug in generator
- Add release package
- Fix document

## 20220911
- Add support for fuzz-introspector
- Migrate to llvm-14.0.6

## 20220921
- Add support for Makefile
- Generation for global function of C++ libraries
- Add testing repository: https://github.com/thientc/Futag-tests

## 20221012
- Add support for AFLplusplus
- Add possibility of building LLVM with different version (12, 13, 14)
- Add analysis for classes, structs, unions...
- Add compilition database of building
- Add analysis of headers

## 20221018
- Add support for C++, generate for constructors and for method of class, which has default constructors
- Tested on FreeImage and Pugixml