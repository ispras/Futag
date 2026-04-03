# Futag Checker Architecture

This document describes the C++ Clang Static Analyzer checkers that form the core analysis layer of Futag. These checkers extract function signatures, type information, and usage contexts from C/C++ library source code, producing JSON output consumed by the Python generator layer.

## Overview

Futag uses two custom Clang checkers integrated into the LLVM Static Analyzer:

1. **FutagAnalyzer** -- Analyzes **library** source code to extract function declarations, type definitions (structs, enums, typedefs), and call contexts.
2. **FutagConsumerAnalyzer** -- Analyzes **consumer** programs that use the library, extracting usage contexts: how library functions are called, what arguments are passed, and in what order.

### Data Flow

```
Library Source Code
        |
        v
  [FutagAnalyzer]  (Clang checker, runs via scan-build)
        |
        v
  JSON analysis files:
    .declaration-*.json  (function signatures)
    .context-*.json      (call contexts)
    .types-info-*.json   (enums, records, typedefs)
    .file-info-*.json    (includes, compiler options)
        |
        v
  futag-analysis-result.json  (aggregated by Python preprocessor.py)
        |
        +---> [Python Generator]  (generates fuzz targets)
        |
        v
  futag-4consumer.json  (subset for consumer analysis)
        |
        v
Consumer Source Code + futag-4consumer.json
        |
        v
  [FutagConsumerAnalyzer]  (Clang checker)
        |
        v
  _funcname_varname_blocks.json  (per-context files)
        |
        v
  futag-contexts.json  (aggregated by Python preprocessor.py)
        |
        v
  [Python ContextGenerator]  (generates context-based fuzz targets)
```

## Checker Registration

Checkers are defined in `analyzers/checkers/include/Checkers.td` using Clang's TableGen format:

```tablegen
let ParentPackage = Futag in {
    def FutagAnalyzer : Checker<"FutagAnalyzer">,
        CheckerOptions<[
            CmdLineOption<String, "report_dir",
                "Absolute path to the directory, where to write results",
                "/tmp/futag-function-analyzer-reports/", Released>,
        ]>;

    def FutagConsumerAnalyzer : Checker<"FutagConsumerAnalyzer">,
        CheckerOptions<[
            CmdLineOption<String, "consumer_report_path", ...>,
            CmdLineOption<String, "db_filepath", ...>,
        ]>;
}
```

Invoked via `scan-build`:
```bash
scan-build -enable-checker futag.FutagAnalyzer \
    -analyzer-config futag.FutagAnalyzer:report_dir=/path/to/output \
    make
```

## FutagAnalyzer

**Source:** `analyzers/checkers/lib/FutagAnalyzer.cpp` (+ LLVM14/18 variants)

### Class Hierarchy

```
FutagAnalyzer : public Checker<check::ASTDecl<TranslationUnitDecl>>
```

The checker hooks into Clang's `ASTDecl` callback, receiving the entire translation unit AST for each compiled file.

### Execution Flow

1. **`registerFutagAnalyzer()`** -- Called by Clang during checker setup. Creates the checker instance, reads the `report_dir` option, and generates random filenames for 4 output JSON files.

2. **`checkASTDecl(TranslationUnitDecl)`** -- Entry point called once per translation unit.
   - Collects include file information from `SourceManager`
   - Creates a `RecursiveASTVisitor` (inner class `LocalVisitor`)
   - Traverses the entire AST

3. **Visitor callbacks:**
   - `VisitFunction(FunctionDecl)` -- For each function: computes ODR hash, extracts signature metadata, determines parameter usage patterns, finds internal call contexts
   - `VisitRecord(RecordDecl)` -- For structs/classes/unions: extracts fields with type info
   - `VisitTypedef(TypedefDecl)` -- For typedefs: extracts underlying type and links to source type
   - `VisitEnum(EnumDecl)` -- For enums: extracts enum values

4. **Destructor** -- Writes all collected JSON data to the output files.

### Key Helper Methods

| Method | Purpose |
|--------|---------|
| `CollectBasicFunctionInfo()` | Extracts: ODR hash, name, location, return type, parameters, function type, access type, storage class, `is_simple` flag |
| `CollectAdvancedFunctionInfo()` | Uses AST matchers to find call expressions within function body; records which functions call which |
| `DetermineArgUsageInAST()` | Classifies how each parameter is used (file path, size field, C string, etc.) via `ArgumentsUsage` |
| `WriteInfoToTheFile()` | Writes JSON data to a file, merging with existing content if the file already exists |

### Data Collected Per Function

```json
{
  "<odr_hash>": {
    "name": "func_name",
    "qname": "namespace::func_name",
    "hash": "12345678",
    "is_simple": true,
    "func_type": 4,
    "access_type": 3,
    "storage_class": 0,
    "parent_hash": "",
    "return_type": { "type_name": "int", "gen_type": 0 },
    "gen_return_type": [{ "gen_type": 0, "type_name": "int", ... }],
    "params": [
      {
        "param_name": "buf",
        "param_type": "char *",
        "param_usage": "C_STRING",
        "gen_list": [{ "gen_type": 1, "type_name": "char *", ... }]
      }
    ],
    "fuzz_it": true,
    "call_contexts": [...],
    "location": "/path/to/file.c:42"
  }
}
```

### Function Type Constants

| Value | Name | Meaning |
|-------|------|---------|
| 0 | `_FUNC_CXXMETHOD` | C++ class method |
| 1 | `_FUNC_CONSTRUCTOR` | C++ constructor |
| 2 | `_FUNC_DEFAULT_CONSTRUCTOR` | C++ default constructor |
| 3 | `_FUNC_DESTRUCTOR` | C++ destructor |
| 4 | `_FUNC_GLOBAL` | Global C function |
| 5 | `_FUNC_STATIC` | Static function |

## FutagConsumerAnalyzer

**Source:** `analyzers/checkers/lib/FutagConsumerAnalyzer.cpp` (+ LLVM14/18 variants)

### Purpose

Analyzes consumer programs to extract **usage contexts** -- how library functions are actually called in real code. This produces structured data that the Python `ContextGenerator` uses to create more realistic fuzz targets.

### Prerequisites

Requires `analysis_jdb` -- the JSON database from a prior `FutagAnalyzer` run (loaded via the `db_filepath` checker option).

### Execution Flow

1. **`registerFutagConsumerAnalyzer()`** -- Creates checker, loads JSON database from `db_filepath`, sets output path.

2. **`checkASTDecl(TranslationUnitDecl)`** -- Entry point. Collects includes, then traverses AST using `RecursiveASTVisitor`.

3. **`AnalyzeVisitedFunctionDecl(FunctionDecl)`** -- Core analysis for each function:

   **Phase 1: Match variable initializations** (AST matching)
   - Uses `FutagMatchInitCallExprCB` to find patterns like `T *var = library_func(...)`
   - Cross-references matched function names against `analysis_jdb`
   - Produces `matched_init_contexts`: map of (variable -> initializing call expression)

   **Phase 2: Build CFG and enumerate paths**
   - Builds the Control Flow Graph (CFG) for the function
   - Functions with >30 CFG blocks are skipped (configurable via `MAX_CFG_BLOCKS`)
   - `FindAllCFGPaths()` recursively enumerates all paths through the CFG

   **Phase 3: For each CFG path, extract ordered call sequence**
   - Maps each init_call to its CFG block position within the path
   - For each init_call's arguments: `SearchVarDeclInBlock()` traces variable definitions backward through preceding CFG blocks
   - `SearchModifyingCallExprInBlock()` finds subsequent calls that modify the initialized variable
   - Writes the context (init_calls + modifying_calls + cfg_blocks) to a JSON file

### CFG Analysis

The analyzer builds a Control Flow Graph for each consumer function and enumerates all execution paths:

```
FindAllCFGPaths(cfg, entry_block, graph, current_path, all_paths)
  For each successor of current block:
    If successor already in path: skip (avoid cycles)
    If successor is exit block: save path
    Else: recurse with successor appended to path
```

### Output Format

Each context file (`_funcname_varname_blocks.json`) contains:

```json
{
  "cfg_blocks": [5, 3, 2, 1, 0],
  "init_calls": {
    "conn": {
      "name": "curl_easy_init",
      "qname": "curl_easy_init",
      "cfg_block_ID": 3,
      "str_stmt": "curl_easy_init()",
      "file": "consumer.c",
      "line": 15,
      "col": 20,
      "args": []
    }
  },
  "modifying_calls": [
    {
      "name": "curl_easy_setopt",
      "qname": "curl_easy_setopt",
      "cfg_block_ID": 2,
      "str_stmt": "curl_easy_setopt(conn, CURLOPT_URL, url)",
      "file": "consumer.c",
      "line": 16,
      "col": 5,
      "args": [
        {"init_type": "ArgVarRef", "value": "conn"},
        {"init_type": "ArgConstValue", "value": "10002"},
        {"init_type": "ArgVarRef", "value": "url"}
      ]
    }
  ]
}
```

## Type System

**Source:** `analyzers/clang-patches/include/Futag/Basic.h`, `analyzers/clang-patches/lib/Futag/Basic.cpp`

### Type Classification

Futag decomposes C/C++ types into a chain of `GenTypeInfo` structs:

```cpp
struct GenTypeInfo {
    FutagGenType gen_type;       // Classification (F_BUILTIN, F_CSTRING, ...)
    std::string base_type_name;  // Unqualified/pointee/element type
    std::string type_name;       // Current qualified type
    std::string local_qualifier; // const, volatile, restrict
    uint64_t length;             // Array length (0 if not array)
};
```

### FutagGenType Enum

| Value | Name | Example |
|-------|------|---------|
| 0 | `F_BUILTIN` | `int`, `float`, `double` |
| 1 | `F_CSTRING` | `char *`, `const char *` |
| 2 | `F_WSTRING` | `wchar_t *` |
| 3 | `F_CXXSTRING` | `std::string` |
| 4 | `F_ENUM` | Any enum type |
| 5 | `F_ARRAY` | `int[10]` |
| 6 | `F_VOIDP` | `void *` |
| 7 | `F_QUALIFIER` | const/volatile wrapper |
| 8 | `F_POINTER` | Any pointer type |
| 9 | `F_STRUCT` | struct types |
| 10 | `F_UNION` | union types |
| 11 | `F_CLASS` | C++ class types |

### Python-side Correspondence

The Python `sysmsg.py` defines matching constants:

| C++ | Python |
|-----|--------|
| `F_BUILTIN` (0) | `GEN_BUILTIN` (0) |
| `F_CSTRING` (1) | `GEN_CSTRING` (1) |
| `F_STRUCT` (9) | `GEN_STRUCT` (9) |
| ... | ... |

### Key Functions

- `getGenType(QualType)` -- Recursively decomposes a type into a vector of `GenTypeInfo`
- `getGenField(QualType)` -- Similar but for struct field types
- `isSimpleType(QualType)` -- Returns true if the type (or its pointee) is a builtin type
- `isSimpleFunction(FunctionDecl)` -- Returns true if all parameters are simple types

## AST Matching Infrastructure

### FutagAnalyzer Matchers (`analyzers/clang-patches/include/Futag/MatchFinder.h`)

| Callback Class | Pattern Matched | Purpose |
|----------------|-----------------|---------|
| `FutagMatchCallExprCallBack` | `callExpr(callee(functionDecl(...)))` | Finds function calls within a function body; records caller/callee relationship |
| `FutagArgUsageDeterminer` | `callExpr(hasAnyArgument(hasDescendant(declRefExpr(to(varDecl(hasName(...)))))))` | Determines how a parameter is used (file path, size, string, etc.) |
| `FutagMatchVarDeclArgCallBack` | Variable declaration matching | Tracks variable initializations |
| `FutagMatchBinOperatorArgCallBack` | Assignment operator matching | Tracks variable assignments |

### FutagConsumerAnalyzer Matchers (`analyzers/clang-patches/include/Futag/ConsumerFinder.h`)

| Callback Class | Pattern Matched | Purpose |
|----------------|-----------------|---------|
| `FutagMatchInitCallExprCB` | `varDecl(hasInitializer(callExpr(...)))` | Finds `T *var = func(...)` patterns |
| `FutagMatchDefCallExprCB` | `binaryOperator(isAssignment, hasRHS(callExpr(...)))` | Finds `var = func(...)` patterns |
| `FutagMatchModCallExprCB` | `callExpr(hasDescendant(declRefExpr(to(varDecl(hasName(...))))))` | Finds calls that reference a specific variable |

### Helper Functions (ConsumerFinder.cpp)

| Function | Purpose |
|----------|---------|
| `GetCallExprInfo()` | Extracts detailed info from a `CallExpr`: function name, arguments (with types), location, CFG block |
| `SearchVarDeclInBlock()` | Searches a CFG block for variable definitions that use library function calls |
| `SearchModifyingCallExprInBlock()` | Searches a CFG block for calls that reference a specific variable |
| `HandleLiterals()` | Converts `Expr` literal types to `FutagInitArg` with appropriate type classification |

## JSON Output Format

### FutagAnalyzer Output Files

All files are written to the `report_dir` with random suffixes to avoid collisions during parallel compilation.

| File Pattern | Content |
|---|---|
| `.declaration-<rand>.futag-analyzer.json` | Function declarations keyed by ODR hash |
| `.context-<rand>.futag-analyzer.json` | Function call contexts (which functions call which) |
| `.types-info-<rand>.futag-analyzer.json` | `{"enums": [...], "records": [...], "typedefs": [...]}` |
| `.file-info-<rand>.futag-analyzer.json` | `{"file": "path", "includes": [...], "compiler_opts": "..."}` |

### FutagConsumerAnalyzer Output Files

Written to `consumer_report_path`:

| File Pattern | Content |
|---|---|
| `_<funcname>_<varname>_<blocks>.json` | Per-context file with `{cfg_blocks, init_calls, modifying_calls}` |

## LLVM Version Handling

The project maintains version-specific copies of files for LLVM 14 and 18 compatibility:

| Base File | LLVM 14 | LLVM 18 |
|-----------|---------|---------|
| `FutagAnalyzer.cpp` | `FutagAnalyzer14.cpp` | `FutagAnalyzer18.cpp` |
| `FutagConsumerAnalyzer.cpp` | `FutagConsumerAnalyzer14.cpp` | `FutagConsumerAnalyzer18.cpp` |
| `ASTMatchFinder.h` | `ASTMatchFinder14.h` | `ASTMatchFinder18.h` |
| `CMakeLists.txt` | `CMakeLists14.txt` | `CMakeLists18.txt` |
| `Checkers.td` | `Checkers14.td` | `Checkers18.td` |

**Key API differences:**
- LLVM 14: `SourceManager::fileinfo_iterator` yields pointers (`it->first->getName()`)
- LLVM 18+: `SourceManager::fileinfo_iterator` yields objects (`it->first.getName()`)

The base file always matches the LLVM 18 version. The `build.sh` script selects the correct version-specific files during LLVM compilation.

## Build Integration

### Checker Compilation

Checkers are compiled into Clang's `clangStaticAnalyzerCheckers` library:

```cmake
# analyzers/checkers/lib/CMakeLists.txt
add_clang_library(clangStaticAnalyzerCheckers
    ...
    FutagAnalyzer.cpp
    FutagConsumerAnalyzer.cpp
    ...
)
```

### Helper Library

Supporting code is built as `FutagLib`:

```cmake
# analyzers/clang-patches/lib/Futag/CMakeLists.txt
add_clang_library(FutagLib
    Basic.cpp
    MatchFinder.cpp
    ConsumerFinder.cpp
)
```

### Dependencies

- **nlohmann/json** (`vendors/json-3.10.5/`) -- JSON serialization for all output
- **Clang AST/ASTMatchers** -- AST traversal and pattern matching
- **Clang Analysis/CFG** -- Control flow graph construction (Consumer only)
