# Futag Generator Architecture

This document describes the Python generator subsystem that produces C/C++ fuzz targets from the JSON analysis output of the Futag Clang checkers.

## Overview

The generator reads `futag-analysis-result.json` (produced by `FutagAnalyzer` + `preprocessor.py`) and generates fuzz driver source files that exercise library functions with random data. Multiple generator backends exist, differing only in how they consume fuzzing input.

### Class Hierarchy

```
BaseGenerator (ABC)                    # base_generator.py (~2100 lines)
    |-- Generator                      # generator.py - memcpy from raw buffer
    |-- FuzzDataProviderGenerator      # fdp_generator.py - libFuzzer FDP API
    |     \-- BlobStamperGenerator     # blob_stamper_generator.py - inherits FDP
    |-- ContextGenerator               # generator.py (to be extracted)
    \-- NatchGenerator                 # generator.py (to be extracted)
```

### Data Flow

```
futag-analysis-result.json
    |
    v
BaseGenerator.__init__()  -->  self.target_library (dict)
    |
    v
gen_targets()  -->  iterates functions, categorizes by type
    |
    v
_gen_target_function(func, param_id)  -->  recursive parameter generation
    |                                        |
    |                                        v
    |                               _gen_builtin / _gen_cstring / _gen_struct / etc.
    |                                        |
    |                                        v
    |                               writes .c/.cpp wrapper file
    v
compile_targets()  -->  parallel compilation via multiprocessing.Pool
    |
    v
succeeded/ and failed/ directories with compiled fuzz drivers
```

## BaseGenerator (ABC)

**File:** `futag-package/src/futag/base_generator.py`

The abstract base class containing all shared infrastructure. Subclasses only need to implement 10 type-specific generation methods.

### Configuration Properties

| Property | Type | Default | Purpose |
|----------|------|---------|---------|
| `default_headers` | `list[str]` | C standard headers | Default `#include` headers for generated files |
| `supports_c` | `bool` | `True` | Whether to support C targets (vs C++ only) |
| `needs_buffer_check` | `bool` | `True` | Whether to generate buffer size validation |
| `harness_preamble` | `str` | `""` | Extra code after harness prefix (e.g., FDP init) |

### Abstract Methods (10)

These are the **only** methods subclasses must implement:

| Method | Purpose | Returns |
|--------|---------|---------|
| `_gen_builtin(param_name, gen_type_info)` | Generate builtin types (int, float, etc.) | `dict(gen_lines, gen_free, buffer_size)` |
| `_gen_strsize(param_name, param_type, dyn_size_idx, array_name)` | Generate string size parameters | `dict(...)` |
| `_gen_cstring(param_name, gen_type_info, dyn_cstring_size_idx)` | Generate C strings | `dict(...)` |
| `_gen_wstring(param_name, gen_type_info, dyn_wstring_size_idx)` | Generate wide strings | `dict(...)` |
| `_gen_cxxstring(param_name, gen_type_info, dyn_cxxstring_size_idx)` | Generate C++ strings | `dict(...)` |
| `_gen_enum(enum_record, param_name, gen_type_info, compiler_info, anonymous)` | Generate enums | `dict(...)` |
| `_gen_array(param_name, gen_type_info)` | Generate arrays | `dict(...)` |
| `_gen_void(param_name)` | Generate void pointers | `dict(...)` |
| `_gen_qualifier(param_name, prev_param_name, gen_type_info)` | Generate const/volatile types | `dict(...)` |
| `_gen_pointer(param_name, prev_param_name, gen_type_info)` | Generate pointer types | `dict(...)` |

Each returns a dict with three keys:
- `gen_lines`: List of C/C++ code strings
- `gen_free`: List of cleanup code strings
- `buffer_size`: List of size expression strings

### Public API

```python
# Create generator
gen = Generator(futag_llvm_package="/path/to/futag-llvm",
                library_root="/path/to/library")

# Generate fuzz targets
gen.gen_targets(anonymous=False, max_wrappers=10, max_functions=10000)

# Compile with parallel workers
gen.compile_targets(workers=4, keep_failed=True, coverage=True)
```

## GeneratorState

**File:** `futag-package/src/futag/generator_state.py`

Dataclass encapsulating all mutable state during recursive target generation. Replaces the previous pattern of 13+ instance variables with manual save/restore.

```python
state = GeneratorState()
saved = state.save()        # Deep copy for backtracking
state.restore_from(saved)   # Restore from saved copy
state.reset()               # Clear all state for new function
```

## Generator Backends

### Generator (Standard)

**File:** `futag-package/src/futag/generator.py`

Uses raw `memcpy()` from a byte buffer (`uint8_t *futag_pos`). Supports both C and C++ targets.

```c
// Generated code example:
int param1;
memcpy(&param1, futag_pos, sizeof(int));
futag_pos += sizeof(int);
```

### FuzzDataProviderGenerator

**File:** `futag-package/src/futag/fdp_generator.py`

Uses libFuzzer's `FuzzedDataProvider` API for type-safe data consumption. C++ only.

```cpp
// Generated code example:
FuzzedDataProvider provider(Fuzz_Data, Fuzz_Size);
auto param1 = provider.ConsumeIntegral<int>();
std::string s_fdp = provider.ConsumeRandomLengthString();
const char* param2 = s_fdp.c_str();
```

### BlobStamperGenerator

**File:** `futag-package/src/futag/blob_stamper_generator.py`

Inherits from `FuzzDataProviderGenerator`. Same type generation logic but supports both C and C++ targets.

### ContextGenerator

Generates fuzz targets from consumer program usage contexts (produced by `FutagConsumerAnalyzer`). Uses `futag-contexts.json` in addition to the analysis result.

### NatchGenerator

Generates fuzz targets from Natch crash traces. Operates on a subset of functions identified by Natch.

## How to Add a New Generator Backend

1. Create a new file (e.g., `my_generator.py`)
2. Subclass `BaseGenerator`
3. Set configuration properties
4. Implement the 10 abstract `_gen_*` methods

```python
from futag.base_generator import BaseGenerator
from futag.sysmsg import *

class MyGenerator(BaseGenerator):
    @property
    def default_headers(self):
        return ["stdio.h", "stddef.h", "my_custom_header.h"]

    @property
    def supports_c(self):
        return True

    @property
    def needs_buffer_check(self):
        return True

    @property
    def harness_preamble(self):
        return "    // My custom initialization\n"

    def _gen_builtin(self, param_name, gen_type_info):
        return {
            "gen_lines": [f"auto {param_name} = my_consume<{gen_type_info['type_name']}>();\n"],
            "gen_free": [],
            "buffer_size": []
        }

    # ... implement remaining 9 methods
```

## JSON Input Format

The generator reads `futag-analysis-result.json` with this structure:

```json
{
  "functions": [{
    "name": "func_name",
    "qname": "namespace::func_name",
    "hash": "12345678",
    "is_simple": true,
    "func_type": 4,
    "access_type": 3,
    "storage_class": 0,
    "parent_hash": "",
    "return_type": {"type_name": "int"},
    "gen_return_type": [{"gen_type": 0, "type_name": "int", ...}],
    "params": [{
      "param_name": "buf",
      "param_type": "const char *",
      "param_usage": "UNKNOWN",
      "gen_list": [{"gen_type": 1, "type_name": "const char *", "base_type_name": "char", "local_qualifier": "const", "length": 0}]
    }],
    "fuzz_it": true,
    "contexts": [],
    "location": {"file": "test.c", "line": "10", "directory": "/src", "fullpath": "/src/test.c"}
  }],
  "enums": [{"name": "Color", "qname": "Color", "hash": "...", "enum_values": [{"field_name": "RED", "value": 0}]}],
  "records": [{"name": "Point", "qname": "Point", "hash": "...", "record_type": 2, "fields": [...]}],
  "typedefs": [{"name": "size_type", "underlying_type": "unsigned long", ...}],
  "compiled_files": [{"filename": "/src/test.c", "headers": ["\"test.h\""], "include_paths": ["/src"], "compiler_opts": ["-I/src"]}]
}
```

### gen_type Constants (from sysmsg.py)

| Value | Name | C/C++ Type |
|-------|------|------------|
| 0 | `GEN_BUILTIN` | int, float, double, etc. |
| 1 | `GEN_CSTRING` | char *, const char * |
| 2 | `GEN_WSTRING` | wchar_t * |
| 3 | `GEN_CXXSTRING` | std::string |
| 4 | `GEN_ENUM` | enum types |
| 5 | `GEN_ARRAY` | fixed-size arrays |
| 6 | `GEN_VOID` | void * |
| 7 | `GEN_QUALIFIER` | const/volatile wrapper |
| 8 | `GEN_POINTER` | pointer types |
| 9 | `GEN_STRUCT` | struct types |
| 10 | `GEN_UNION` | union types |
| 11 | `GEN_CLASS` | C++ class types |

## Generated Output Structure

```
library_root/
    futag-fuzz-drivers/           # Final output
        succeeded/                # Successfully compiled drivers
            func_name/
                func_name.1/
                    func_name.1.c     # Source
                    func_name.1.out   # Binary
        failed/                   # Failed compilation (if keep_failed=True)
    .futag-fuzz-drivers/          # Temporary build directory
```
