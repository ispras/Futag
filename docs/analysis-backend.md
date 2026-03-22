# Alternative Analysis Backends

This guide explains how to produce a `futag-analysis-result.json` file from tools other than Futag's built-in Clang checkers (e.g., CodeQL, Joern, or custom analyzers).

## Overview

Futag's Python generators consume a single JSON file — `futag-analysis-result.json` — that describes library functions, types, and compilation metadata. The generators do not care how this JSON was produced. Any tool that can output this format can serve as an analysis backend.

See [analysis-schema.json](analysis-schema.json) for the formal JSON Schema specification.

## Usage Modes

| Mode | What you need | Example |
|------|---------------|---------|
| Full pipeline | futag-llvm toolchain | `Builder(FUTAG_PATH, lib_root)` → `Generator(FUTAG_PATH, lib_root)` |
| Pre-built JSON + system clang | analysis JSON + any clang | `Generator(library_root=lib_root, json_file="analysis.json", toolchain=ToolchainConfig.from_system())` |
| Generation only | analysis JSON only | `Generator(library_root=lib_root, json_file="analysis.json")` → produces `.c`/`.cpp` source files |

## Required vs Optional Fields

### Required for `gen_targets()` (source code generation)

- `functions[]` — at least the `name`, `qname`, `func_type`, `access_type`, `params`, `fuzz_it`, and `location` fields
- `functions[].params[].gen_list` — the type decomposition chain (this is the critical data structure)
- `enums[]` — needed if any parameter has `gen_type: 4` (GEN_ENUM)
- `records[]` — needed if any parameter has `gen_type: 9/10/11` (struct/union/class)

### Required for `compile_targets()` (compilation)

- `compiled_files[]` — include paths and compiler flags per source file

### Optional

- `typedefs[]` — used for type resolution but not strictly required
- `functions[].contexts` — only used by `ContextGenerator`
- `functions[].gen_return_type` — used for some return type analysis

## The `gen_list` Type Decomposition

The most important data structure is `gen_list` — an array of `GenTypeInfo` objects that describes how to decompose a C/C++ type for code generation.

### gen_type Values

| Value | Name | C/C++ Example | What the generator does |
|-------|------|---------------|------------------------|
| 0 | GEN_BUILTIN | `int`, `float`, `double` | `memcpy(&x, buf, sizeof(int))` |
| 1 | GEN_CSTRING | `char *`, `const char *` | `malloc` + `memcpy` + null terminator |
| 2 | GEN_WSTRING | `wchar_t *` | Wide string allocation |
| 3 | GEN_CXXSTRING | `std::string` | `std::string` construction |
| 4 | GEN_ENUM | `enum Color` | Index into enum values array |
| 5 | GEN_ARRAY | `int[10]` | `malloc(sizeof(int) * 10)` |
| 6 | GEN_VOID | `void *` | `NULL` (cannot generate meaningful data) |
| 7 | GEN_QUALIFIER | `const int` | Reference to underlying variable |
| 8 | GEN_POINTER | `int *` | `&` address-of underlying variable |
| 9 | GEN_STRUCT | `struct Point` | Field-by-field initialization |
| 10 | GEN_UNION | `union Data` | First-field initialization |
| 11 | GEN_CLASS | `class MyClass` | Constructor call |
| 12 | GEN_INCOMPLETE | incomplete types | Skipped |
| 13 | GEN_FUNCTION | `void (*)(int)` | `NULL` (function pointer) |
| 14 | GEN_INPUT_FILE | file path (read) | Generate temp file path |
| 15 | GEN_OUTPUT_FILE | file path (write) | Generate temp file path |
| 18 | GEN_UNKNOWN | unknown types | Skipped |

### Decomposition Examples

**Simple: `int x`**
```json
"gen_list": [
  {"gen_type": 0, "type_name": "int", "base_type_name": "int", "local_qualifier": "", "length": 0}
]
```

**Pointer: `const char *s`**
```json
"gen_list": [
  {"gen_type": 1, "type_name": "const char *", "base_type_name": "char", "local_qualifier": "const", "length": 0}
]
```

**Array: `int arr[10]`**
```json
"gen_list": [
  {"gen_type": 5, "type_name": "int *", "base_type_name": "int", "length": 10}
]
```

## `param_usage` Classification

The `param_usage` field helps the generator produce more realistic inputs:

| Value | Meaning | Generator behavior |
|-------|---------|-------------------|
| `UNKNOWN` | No special semantics | Generate from type info only |
| `FILE_PATH_READ` | Read-only file path | Generate temp file with random content |
| `FILE_PATH_WRITE` | Write file path | Generate temp file path |
| `FILE_PATH_RW` | Read-write file path | Generate temp file with random content |
| `FILE_PATH` | Generic file path | Generate temp file path |
| `SIZE_FIELD` | Size of a preceding buffer | Link to buffer size variable |
| `C_STRING` | Used as a C string | Ensure null termination |

### Heuristics for Classification

When building a backend, use these heuristics:
- **FILE_PATH**: parameter name contains "path", "file", "filename", "dir" AND type is `char *`
- **SIZE_FIELD**: parameter follows a pointer/array parameter AND has integer type AND name contains "size", "len", "count", "num"
- **C_STRING**: type is `char *` or `const char *` AND used in string operations (`strcmp`, `strlen`, `strcpy`, etc.)
- **UNKNOWN**: default for all other parameters

## Minimal Example

A complete JSON for a library with one function `int add(int a, int b)`:

```json
{
  "functions": [
    {
      "name": "add",
      "qname": "add",
      "hash": "abc123",
      "is_simple": true,
      "func_type": 4,
      "access_type": 3,
      "storage_class": 0,
      "parent_hash": "",
      "return_type": {"type_name": "int"},
      "gen_return_type": [{"gen_type": 0, "type_name": "int", "base_type_name": "int", "local_qualifier": "", "length": 0}],
      "params": [
        {
          "param_name": "a",
          "param_type": "int",
          "param_usage": "UNKNOWN",
          "gen_list": [{"gen_type": 0, "type_name": "int", "base_type_name": "int", "local_qualifier": "", "length": 0}]
        },
        {
          "param_name": "b",
          "param_type": "int",
          "param_usage": "UNKNOWN",
          "gen_list": [{"gen_type": 0, "type_name": "int", "base_type_name": "int", "local_qualifier": "", "length": 0}]
        }
      ],
      "fuzz_it": true,
      "contexts": [],
      "location": {"file": "math.c", "line": "5", "directory": "/src", "fullpath": "/src/math.c"}
    }
  ],
  "enums": [],
  "records": [],
  "typedefs": [],
  "compiled_files": [
    {
      "filename": "/src/math.c",
      "headers": ["\"math.h\""],
      "include_paths": ["/src"],
      "compiler_opts": "-I/src"
    }
  ]
}
```

## CodeQL Integration Notes

For CodeQL users, these QL predicates map to the required JSON fields:

| JSON field | CodeQL predicate |
|-----------|-----------------|
| `functions[].name` | `Function.getName()` |
| `functions[].qname` | `Function.getQualifiedName()` |
| `functions[].params` | `Function.getParameter(i)` |
| `params[].param_type` | `Parameter.getType().toString()` |
| `enums` | `EnumType` + `EnumConstant` |
| `records` | `Struct`, `Union`, `Class` |
| `compiled_files` | Compilation database (`compile_commands.json`) |

The `gen_list` type decomposition requires recursive type analysis — start from the parameter type and unwrap qualifiers, pointers, and arrays. The `hash` field can be any unique identifier (CodeQL uses `getUniqueId()`).
