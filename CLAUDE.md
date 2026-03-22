# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FUTAG (Fuzz target Automated Generator) is a tool from ISP RAS for automated generation of fuzzing wrappers (fuzz targets) for software libraries. It analyzes library source code via custom Clang/LLVM static analysis checkers and generates fuzz targets in LibFuzzer or AFLplusplus format.

## Build Commands

### Building the custom LLVM/Clang toolchain

```bash
# 1. Download LLVM sources (interactive - select LLVM version)
cd build-llvm && ./prepare.sh

# 2. Build LLVM with Futag checkers integrated
cd ../build && ./build.sh

# Output: futag-llvm/ directory with compiled toolchain
```

### Building AFLplusplus support (optional)

```bash
cd futag-llvm && ./buildAFLplusplus.sh
```

### Installing the Python package

```bash
cd futag-package && pip install .
```

### Running integration tests (Docker)

Tests are Dockerized per platform in `integration-tests/`:
- `integration-tests/build-test/` — build validation on Ubuntu 20.04/22.04/24.04, Alt 11/12
- `integration-tests/libraries-test/` — end-to-end tests against real libraries (json-c, php, FreeImage, etc.)
- `integration-tests/package-test/` — Python package tests

## Architecture

### Three-layer design

1. **C++ Clang Checkers** (`analyzers/checkers/`, `analyzers/clang-patches/`) — Static analysis plugins that run inside Clang's StaticAnalyzer to extract function signatures, types, and usage patterns from library code. Version-specific implementations exist for LLVM 14 and 18 (files suffixed `14`/`18`).

2. **Python Orchestration** (`futag-package/src/futag/`) — User-facing API that drives the full pipeline:
   - `preprocessor.py` — `Builder` builds and analyzes target libraries; `ConsumerBuilder` handles library+consumer pairs
   - `generator.py` — `Generator` produces fuzz targets from analysis JSON; `ContextGenerator` uses consumer usage contexts
   - `fuzzer.py` — `Fuzzer` executes generated targets with configurable timeouts, memory limits, and sanitizers
   - `sysmsg.py` — Constants and error messages (LIBFUZZER, AFLPLUSPLUS engine identifiers, paths)

3. **Build Infrastructure** (`build-llvm/`) — Shell scripts that download LLVM sources, patch in Futag's checkers and clang modifications, and build the complete toolchain via CMake.

### Data flow

`Builder.auto_build()` → `Builder.analyze()` (runs Clang checkers, produces JSON) → `Generator.gen_targets()` (reads JSON, writes C fuzz targets) → `Generator.compile_targets()` (compiles with instrumentation) → `Fuzzer.fuzz()` (runs fuzzing)

### LLVM version handling

The project maintains version-specific copies of several files (e.g., `FutagAnalyzer14.cpp` / `FutagAnalyzer18.cpp`, `ASTMatchFinder14.cpp` / `ASTMatchFinder18.cpp`). The build script (`build.sh`) selects the correct version-specific `CMakeLists.txt` and source files during LLVM compilation.

### Key third-party code

- `vendors/json/` — nlohmann/json for C++ JSON serialization in checkers
- `.clang-format` — LLVM style formatting for C++ code

### Recent refactoring (2024)

The Python package underwent major refactoring:
- **BaseGenerator ABC** (`base_generator.py`) — shared infrastructure for all 5 generator subclasses
- **GeneratorState** (`generator_state.py`) — dataclass replacing 13 mutable instance variables
- **BaseFuzzer** (`fuzzer.py`) — shared fuzzer logic; Fuzzer and NatchFuzzer are thin subclasses
- **Custom exceptions** (`exceptions.py`) — FutagError hierarchy replacing sys.exit()
- Generator classes use single-underscore protected methods for proper inheritance

### Running Python tests

```bash
cd futag-package
pip install -e ".[test]"
python -m pytest tests/ -v
```

### Python module structure

```
src/futag/
    base_generator.py        # BaseGenerator ABC (~2500 lines)
    generator.py             # Generator + re-exports (~235 lines)
    fdp_generator.py         # FuzzDataProviderGenerator (~220 lines)
    blob_stamper_generator.py # BlobStamperGenerator (~40 lines)
    context_generator.py     # ContextGenerator (~820 lines)
    natch_generator.py       # NatchGenerator (~1240 lines)
    generator_state.py       # GeneratorState dataclass (~85 lines)
    preprocessor.py          # Builder, ConsumerBuilder (~960 lines)
    fuzzer.py                # BaseFuzzer, Fuzzer, NatchFuzzer (~900 lines)
    toolchain.py             # ToolchainConfig dataclass (~140 lines)
    exceptions.py            # FutagError hierarchy
    sysmsg.py                # Constants and messages
```

## System Requirements

- CMake >= 3.13.4, GCC >= 7.1.0, Python >= 3.8, pip >= 22.1.1
- On Ubuntu: `python-is-python3`, `gcc-multilib`, `binutils-gold`, `binutils-dev`

## Typical Python API usage

```python
from futag.preprocessor import *
from futag.generator import *

builder = Builder(FUTAG_PATH, library_root, clean=True)
builder.auto_build()
builder.analyze()

generator = Generator(FUTAG_PATH, library_root)
generator.gen_targets(anonymous=False, max_wrappers=10)
generator.compile_targets(4)  # parallel workers
```

See `scripts/template-script.py` for a complete workflow example and `workshop/` for library-specific tutorials.
