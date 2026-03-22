# Futag Architecture Overview

This document describes the architecture of FUTAG (Fuzz target Automated Generator),
a tool from ISP RAS for automated generation of fuzzing wrappers (fuzz targets) for
C/C++ software libraries. Futag analyzes library source code via custom Clang/LLVM
static analysis checkers and generates fuzz targets in LibFuzzer or AFLplusplus format.

## Three-Layer Architecture

```
+---------------------------------------------------------------+
|                      Layer 1: Build Infrastructure            |
|         build-llvm/prepare.sh  -->  build/build.sh            |
|   (download LLVM sources, patch Futag checkers, compile)      |
+---------------------------------------------------------------+
                            |
                    futag-llvm/ toolchain
                            |
+---------------------------------------------------------------+
|                Layer 2: C++ Clang Checkers                    |
|          analyzers/checkers/  analyzers/clang-patches/         |
|  (StaticAnalyzer plugins: extract function signatures,        |
|   types, and usage patterns from library source code)         |
+---------------------------------------------------------------+
                            |
                   JSON analysis data
                            |
+---------------------------------------------------------------+
|              Layer 3: Python Orchestration                    |
|           futag-package/src/futag/                            |
|                                                               |
|  preprocessor.py --> generator.py --> fuzzer.py               |
|  (build & analyze)  (gen targets)   (run fuzzing)             |
+---------------------------------------------------------------+
```

### Layer 1: Build Infrastructure (optional, one-time)

Located in `build-llvm/` and `build/`, shell scripts that:

1. Download LLVM sources (`build-llvm/prepare.sh`)
2. Patch in Futag's checkers and Clang modifications
3. Build the complete toolchain via CMake (`build/build.sh`)
4. Optionally build AFLplusplus support (`futag-llvm/buildAFLplusplus.sh`)

**Note:** This layer is only needed for the full pipeline workflow. The Python
package can also work with pre-built analysis JSON and system-installed clang,
or in generation-only mode. See [Usage Modes](#usage-modes) below.

## Data Flow

```
 Library            Futag LLVM             Python Package
 Source Code        Toolchain              (futag)
     |                  |                      |
     v                  v                      |
 +----------+    +-------------+               |
 | .c / .h  |--->| scan-build  |               |
 | files    |    | (checkers)  |               |
 +----------+    +------+------+               |
                        |                      |
                  JSON analysis                |
                  data files                   |
                        |                      v
                        |            +-------------------+
                        +----------->| preprocessor.py   |
                                     | Builder.analyze() |
                                     +--------+----------+
                                              |
                                futag-analysis-result.json
                                              |
                                              v
                                     +-------------------+
                                     | generator.py      |
                                     | gen_targets()     |
                                     +--------+----------+
                                              |
                                     .c / .cpp fuzz targets
                                              |
                                              v
                                     +-------------------+
                                     | generator.py      |
                                     | compile_targets() |
                                     +--------+----------+
                                              |
                                     instrumented binaries
                                              |
                                              v
                                     +-------------------+
                                     | fuzzer.py         |
                                     | Fuzzer.fuzz()     |
                                     +--------+----------+
                                              |
                                              v
                                     crashes / coverage
```

### Layer 2: C++ Clang Checkers

Located in `analyzers/checkers/` and `analyzers/clang-patches/`, these are static analysis plugins that
run inside Clang's StaticAnalyzer framework. They extract function signatures, type
information, and usage patterns from the target library's source code and serialize
the results as JSON.

For detailed documentation, see [docs/checkers.md](checkers.md).

### Layer 3: Python Orchestration

Located in `futag-package/src/futag/`, this layer provides the user-facing
Python API that drives the full pipeline:

- **preprocessor.py** -- `Builder` builds and analyzes target libraries;
  `ConsumerBuilder` handles library+consumer pairs
- **generator.py** -- `Generator` produces fuzz targets from analysis JSON;
  `ContextGenerator` uses consumer usage contexts
- **fuzzer.py** -- `BaseFuzzer`, `Fuzzer`, and `NatchFuzzer` execute generated
  targets with configurable timeouts, memory limits, and sanitizers
- **sysmsg.py** -- Constants and error messages (LIBFUZZER, AFLPLUSPLUS engine
  identifiers, paths)

For detailed documentation, see [docs/generators.md](generators.md) and
[docs/python-api.md](python-api.md).


## Usage Modes

The Python package supports three usage modes via `ToolchainConfig`:

| Mode | Requires | Use case |
|------|----------|----------|
| Full pipeline | futag-llvm toolchain | First-time setup, complete workflow |
| Pre-built JSON + system clang | Any clang + analysis JSON | CodeQL or other backend, CI/CD |
| Generation only | Just the analysis JSON file | Produce source files, compile elsewhere |

```python
from futag.toolchain import ToolchainConfig

# Mode 1: Full pipeline (existing workflow, unchanged)
generator = Generator(FUTAG_PATH, library_root)

# Mode 2: Pre-built JSON + system clang
tc = ToolchainConfig.from_system()
generator = Generator(library_root=lib_root, json_file="analysis.json", toolchain=tc)

# Mode 3: Generation only (no compiler needed)
generator = Generator(library_root=lib_root, json_file="analysis.json")
generator.gen_targets()  # produces .c/.cpp source files
```

The JSON interface between analysis backends and generators is formally specified
in [analysis-schema.json](analysis-schema.json). For instructions on producing
compatible JSON from alternative tools, see [analysis-backend.md](analysis-backend.md).

## Key Components

| Component | Location | Documentation |
|-----------|----------|---------------|
| Clang Checkers | `analyzers/checkers/`, `analyzers/clang-patches/` | [docs/checkers.md](checkers.md) |
| Generator Classes | `futag-package/src/futag/` | [docs/generators.md](generators.md) |
| Python API | `futag-package/` | [docs/python-api.md](python-api.md) |
| Build Scripts | `build-llvm/`, `build/` | [README.en.md](../README.en.md) |
| JSON Schema | `docs/analysis-schema.json` | [docs/analysis-backend.md](analysis-backend.md) |

## Directory Structure

```
Futag/
    analyzers/              # C++ analysis layer
        checkers/           # Clang StaticAnalyzer checker sources
        clang-patches/      # Clang modifications for Futag
    build-llvm/             # Scripts to download and patch LLVM sources
    docs/                   # Detailed documentation
        checkers.md         # Clang checker documentation
        generators.md       # Generator class documentation
        python-api.md       # Python API reference
    examples/               # Example scripts and configurations
    futag-package/          # Python package (pip-installable)
        src/futag/          # Core Python modules
        tests/              # Unit tests
    integration-tests/      # Dockerized tests
        build-test/         # Build validation (Ubuntu 20.04/22.04/24.04, Alt 11/12)
        libraries-test/     # End-to-end tests against real libraries
        package-test/       # Python package tests
    scripts/                # Standalone utility scripts
    vendors/
        json/               # nlohmann/json (C++ JSON library for checkers)
    workshop/               # Library-specific tutorials
```

## LLVM Version Support

Futag supports multiple LLVM versions: **14**, **18**, and **19**.

The project maintains version-specific copies of source files using a naming
convention with version suffixes:

| Base File | LLVM 14 | LLVM 18 |
|-----------|---------|---------|
| `FutagAnalyzer.cpp` | `FutagAnalyzer14.cpp` | `FutagAnalyzer18.cpp` |
| `ASTMatchFinder.cpp` | `ASTMatchFinder14.cpp` | `ASTMatchFinder18.cpp` |
| `CMakeLists.txt` | `CMakeLists14.txt` | `CMakeLists18.txt` |
| `Checkers.td` | `Checkers14.td` | `Checkers18.td` |

The build script (`build/build.sh`) detects or accepts the target LLVM version and
selects the correct version-specific files during compilation.

When adding support for a new LLVM version (e.g., 19):

1. Create version-specific source files (e.g., `FutagAnalyzer19.cpp`)
2. Create a version-specific `CMakeLists19.txt`
3. Update `Checkers.td` with a version-specific copy
4. Update `build/build.sh` version detection logic

The base (unsuffixed) file should always match the latest supported LLVM version.

## Getting Started

For build instructions and setup, see [README.en.md](../README.en.md).

For a complete workflow example, see `scripts/template-script.py` and the
`workshop/` directory for library-specific tutorials.
