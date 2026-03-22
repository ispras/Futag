# Futag Python API Reference

## Quick Start

```python
from futag.preprocessor import Builder
from futag.generator import Generator

# Step 1: Build and analyze the library
builder = Builder("/path/to/futag-llvm", "/path/to/library", clean=True)
builder.auto_build()
builder.analyze()

# Step 2: Generate fuzz targets
generator = Generator("/path/to/futag-llvm", "/path/to/library")
generator.gen_targets(anonymous=False, max_wrappers=10)
generator.compile_targets(workers=4, keep_failed=True)
```

## Module Overview

| Module | Classes | Purpose |
|--------|---------|---------|
| `futag.preprocessor` | `Builder`, `ConsumerBuilder` | Build & analyze libraries |
| `futag.generator` | `Generator`, `ContextGenerator`, `NatchGenerator` | Generate fuzz targets |
| `futag.fdp_generator` | `FuzzDataProviderGenerator` | FDP-based fuzz targets |
| `futag.blob_stamper_generator` | `BlobStamperGenerator` | BlobStamper-based targets |
| `futag.fuzzer` | `Fuzzer`, `NatchFuzzer` | Execute fuzz targets |
| `futag.base_generator` | `BaseGenerator` (ABC) | Shared generator infrastructure |
| `futag.toolchain` | `ToolchainConfig` | External tool path configuration |
| `futag.generator_state` | `GeneratorState` | State management dataclass |
| `futag.sysmsg` | (constants) | Constants and error messages |

---

## ToolchainConfig

Centralizes all external tool paths. Supports three factory methods for different usage modes.

```python
from futag.toolchain import ToolchainConfig

# From a compiled futag-llvm directory (existing workflow)
tc = ToolchainConfig.from_futag_llvm("/path/to/futag-llvm")

# From system-installed tools (discovered via PATH)
tc = ToolchainConfig.from_system()

# Generation only — no tools needed, gen_targets() produces source files
tc = ToolchainConfig.for_generation_only()
```

All classes (`Builder`, `Generator`, `Fuzzer`, etc.) accept an optional `toolchain` parameter. If omitted, the toolchain is constructed from `futag_llvm_package` for backward compatibility.

### Usage Modes

```python
# Mode 1: Full pipeline (existing, unchanged)
builder = Builder(FUTAG_PATH, lib_root)
builder.auto_build()
builder.analyze()
generator = Generator(FUTAG_PATH, lib_root)
generator.gen_targets()
generator.compile_targets(4)

# Mode 2: Pre-built JSON + system clang
tc = ToolchainConfig.from_system()
generator = Generator(library_root=lib_root,
                      json_file="/path/to/analysis.json",
                      toolchain=tc)
generator.gen_targets()
generator.compile_targets(4)

# Mode 3: Generation only (no compiler needed)
generator = Generator(library_root=lib_root,
                      json_file="/path/to/analysis.json")
generator.gen_targets()
# produces .c/.cpp source files in futag-fuzz-drivers/
```

---

## Preprocessor Module

### Builder

Builds and analyzes a target library using the Futag-patched Clang toolchain.

```python
from futag.preprocessor import Builder

builder = Builder(
    futag_llvm_package="/path/to/futag-llvm",  # Required: path to compiled toolchain
    library_root="/path/to/library",            # Required: path to library source
    flags="-g -O0",                             # Compiler flags (default: debug + sanitizer + coverage)
    clean=False,                                # Delete futag dirs before starting
    intercept=True,                             # Use intercept-build for compile_commands.json
    build_path=".futag-build",                  # Build directory name
    install_path=".futag-install",              # Install directory name
    analysis_path=".futag-analysis",            # Analysis output directory name
    processes=4,                                # Parallel build workers
    build_ex_params=""                          # Extra build params (e.g., "--with-openssl")
)

builder.auto_build()  # Auto-detect build system (configure/cmake/makefile/meson)
builder.analyze()     # Aggregate checker JSON into futag-analysis-result.json
```

**Build methods:** `build_cmake()`, `build_configure()`, `build_makefile()`, `build_meson()`

**Output:** `.futag-analysis/futag-analysis-result.json`

### ConsumerBuilder

Analyzes a consumer program to extract library usage contexts.

```python
from futag.preprocessor import ConsumerBuilder

consumer_builder = ConsumerBuilder(
    futag_llvm_package="/path/to/futag-llvm",
    library_root="/path/to/library",
    consumer_root="/path/to/consumer",      # Required: consumer program source
    clean=False,
    processes=4,
)

consumer_builder.auto_build()
consumer_builder.analyze()  # Outputs .futag-consumer/futag-contexts.json
```

---

## Generator Module

### Generator (Standard)

Generates fuzz targets using raw `memcpy()` buffer consumption. Supports both C and C++.

```python
from futag.generator import Generator

generator = Generator(
    futag_llvm_package="/path/to/futag-llvm",
    library_root="/path/to/library",
    alter_compiler="",                          # Override compiler path
    target_type=0,                              # 0=LIBFUZZER, 1=AFLPLUSPLUS
    json_file=".futag-analysis/futag-analysis-result.json",
    output_path="futag-fuzz-drivers",           # Output directory
    build_path=".futag-build",
    install_path=".futag-install",
    delimiter=".",                              # Separator in variant directory names
    exclude_headers=None,                       # List of headers to exclude
)

generator.gen_targets(
    anonymous=False,     # Generate for anonymous namespace functions
    from_list="",        # JSON file with function name filter list
    max_wrappers=10,     # Max variants per function
    max_functions=10000, # Stop after N functions
)

generator.compile_targets(
    workers=4,              # Parallel compilation workers
    keep_failed=False,      # Keep failed compilation logs
    extra_params="",        # Extra compiler parameters
    extra_include="",       # Extra include directories
    extra_dynamiclink="",   # Extra dynamic libraries
    flags="",               # Custom compiler flags
    coverage=False,         # Add coverage instrumentation
    keep_original=True,     # Keep .futag-fuzz-drivers temp directory
)
```

### FuzzDataProviderGenerator

Uses libFuzzer's `FuzzedDataProvider` API. C++ only, type-safe data consumption.

```python
from futag.fdp_generator import FuzzDataProviderGenerator

generator = FuzzDataProviderGenerator(
    futag_llvm_package="/path/to/futag-llvm",
    library_root="/path/to/library",
)
generator.gen_targets(anonymous=False, max_wrappers=100)
generator.compile_targets(workers=4, keep_failed=True)
```

### BlobStamperGenerator

Uses LibBlobStamper. Inherits FDP's type generation but supports both C and C++.

```python
from futag.blob_stamper_generator import BlobStamperGenerator

generator = BlobStamperGenerator(
    futag_llvm_package="/path/to/futag-llvm",
    library_root="/path/to/library",
)
```

### ContextGenerator

Generates fuzz targets from consumer program usage contexts.

```python
from futag.generator import ContextGenerator

ctx_gen = ContextGenerator(
    futag_llvm_package="/path/to/futag-llvm",
    library_root="/path/to/library",
    db_json_file=".futag-analysis/futag-analysis-result.json",
    context_json_file=".futag-consumer/futag-contexts.json",
    output_path="futag-context-fuzz-drivers",
)

ctx_gen.gen_context(max_wrappers=10)  # Note: gen_context(), not gen_targets()
ctx_gen.compile_targets(keep_failed=True)
```

### NatchGenerator

Generates fuzz targets from Natch crash trace data.

```python
from futag.generator import NatchGenerator

natch_gen = NatchGenerator(
    futag_llvm_package="/path/to/futag-llvm",
    library_root="/path/to/library",
    json_file="/path/to/natch-output.json",  # Required: Natch JSON file
)

natch_gen.parse_values()  # Parse Natch JSON and create seed corpus
natch_gen.gen_targets()
natch_gen.compile_targets(workers=4)
```

### Creating a Custom Generator

Subclass `BaseGenerator` and implement 10 abstract methods:

```python
from futag.base_generator import BaseGenerator

class MyGenerator(BaseGenerator):
    @property
    def default_headers(self) -> list:
        return ["stdio.h", "my_custom_header.h"]

    @property
    def supports_c(self) -> bool:
        return True

    @property
    def needs_buffer_check(self) -> bool:
        return True

    @property
    def harness_preamble(self) -> str:
        return ""

    def _gen_builtin(self, param_name, gen_type_info) -> dict:
        return {
            "gen_lines": [...],   # C/C++ code to declare and initialize
            "gen_free": [...],    # Cleanup code
            "buffer_size": [...], # Size expressions
        }

    # Implement: _gen_strsize, _gen_cstring, _gen_wstring, _gen_cxxstring,
    #            _gen_enum, _gen_array, _gen_void, _gen_qualifier, _gen_pointer
```

---

## Fuzzer Module

### Fuzzer

Executes generated fuzz targets and collects crashes.

```python
from futag.fuzzer import Fuzzer

fuzzer = Fuzzer(
    futag_llvm_package="/path/to/futag-llvm",
    fuzz_driver_path="futag-fuzz-drivers",   # Directory with compiled fuzz targets
    debug=False,       # Print debug info
    gdb=False,         # Debug crashes with GDB
    svres=False,       # Generate svres XML for Svace
    fork=1,            # LibFuzzer fork mode (1=no fork)
    totaltime=300,     # Total fuzzing time per target (seconds)
    timeout=10,        # Per-test timeout (seconds)
    memlimit=2048,     # RSS memory limit (MB, 0=disabled)
    coverage=False,    # Generate coverage reports
    leak=False,        # Detect memory leaks
    source_path="",    # Source path for coverage HTML
)

fuzzer.fuzz(extra_param="")  # Run fuzzing on all targets
```

### NatchFuzzer

Same as Fuzzer but adds Natch corpus path support.

```python
from futag.fuzzer import NatchFuzzer

fuzzer = NatchFuzzer(
    futag_llvm_package="/path/to/futag-llvm",
    fuzz_driver_path="futag-fuzz-drivers",
    totaltime=60,
    debug=True,
)
fuzzer.fuzz()
```

---

## Constants Reference (sysmsg.py)

### Generation Type Constants (GEN_*)

| Constant | Value | C/C++ Type |
|----------|-------|------------|
| `GEN_BUILTIN` | 0 | int, float, double, etc. |
| `GEN_CSTRING` | 1 | char *, const char * |
| `GEN_WSTRING` | 2 | wchar_t * |
| `GEN_CXXSTRING` | 3 | std::string |
| `GEN_ENUM` | 4 | enum types |
| `GEN_ARRAY` | 5 | fixed-size arrays |
| `GEN_VOID` | 6 | void * |
| `GEN_QUALIFIER` | 7 | const/volatile wrapper |
| `GEN_POINTER` | 8 | pointer types |
| `GEN_STRUCT` | 9 | struct types |
| `GEN_UNION` | 10 | union types |
| `GEN_CLASS` | 11 | C++ class types |
| `GEN_INCOMPLETE` | 12 | incomplete types |
| `GEN_FUNCTION` | 13 | function pointers |
| `GEN_INPUT_FILE` | 14 | file path (input) |
| `GEN_OUTPUT_FILE` | 15 | file path (output) |
| `GEN_UNKNOWN` | 18 | unknown types |

### Function Type Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `FUNC_CXXMETHOD` | 0 | C++ class method |
| `FUNC_CONSTRUCTOR` | 1 | C++ constructor |
| `FUNC_DEFAULT_CONSTRUCTOR` | 2 | C++ default constructor |
| `FUNC_DESTRUCTOR` | 3 | C++ destructor |
| `FUNC_GLOBAL` | 4 | Global C function |
| `FUNC_STATIC` | 5 | Static function |

### Access Type Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `AS_PUBLIC` | 0 | Public access |
| `AS_PROTECTED` | 1 | Protected access |
| `AS_PRIVATE` | 2 | Private access |
| `AS_NONE` | 3 | No specifier (C functions) |

### Fuzz Driver Format

| Constant | Value | Format |
|----------|-------|--------|
| `LIBFUZZER` | 0 | LibFuzzer harness |
| `AFLPLUSPLUS` | 1 | AFL++ harness |
