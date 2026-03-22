"""Shared pytest fixtures for Futag generator tests."""
import json
import os
import pathlib

import pytest


@pytest.fixture
def sample_analysis_json():
    """Minimal valid analysis JSON matching FutagAnalyzer output format.

    Contains:
    - 2 functions: one C global function, one C++ public method
    - 1 enum with 3 values
    - 1 struct with 2 fields
    - 1 typedef
    - 1 compiled_file entry
    """
    return {
        "functions": [
            {
                "name": "test_func",
                "qname": "test_func",
                "hash": "12345678",
                "is_simple": True,
                "func_type": 4,  # FUNC_GLOBAL
                "access_type": 3,  # AS_NONE (C function)
                "storage_class": 0,  # SC_NONE
                "parent_hash": "",
                "return_type": {"type_name": "int"},
                "gen_return_type": [{"gen_type": 0, "type_name": "int", "base_type_name": "int", "local_qualifier": "", "length": 0}],
                "params": [
                    {
                        "param_name": "buf",
                        "param_type": "const char *",
                        "param_usage": "UNKNOWN",
                        "gen_list": [
                            {"gen_type": 1, "type_name": "const char *", "base_type_name": "char", "local_qualifier": "const", "length": 0}
                        ],
                    },
                    {
                        "param_name": "size",
                        "param_type": "int",
                        "param_usage": "SIZE_FIELD",
                        "gen_list": [
                            {"gen_type": 0, "type_name": "int", "base_type_name": "int", "local_qualifier": "", "length": 0}
                        ],
                    },
                ],
                "fuzz_it": True,
                "contexts": [],
                "location": {
                    "file": "test.c",
                    "line": "10",
                    "directory": "/src",
                    "fullpath": "/src/test.c",
                },
            },
            {
                "name": "doWork",
                "qname": "MyClass::doWork",
                "hash": "87654321",
                "is_simple": True,
                "func_type": 0,  # FUNC_CXXMETHOD
                "access_type": 0,  # AS_PUBLIC
                "storage_class": 0,  # SC_NONE
                "parent_hash": "11111111",
                "return_type": {"type_name": "void"},
                "gen_return_type": [{"gen_type": 6, "type_name": "void", "base_type_name": "void", "local_qualifier": "", "length": 0}],
                "params": [
                    {
                        "param_name": "value",
                        "param_type": "int",
                        "param_usage": "UNKNOWN",
                        "gen_list": [
                            {"gen_type": 0, "type_name": "int", "base_type_name": "int", "local_qualifier": "", "length": 0}
                        ],
                    },
                ],
                "fuzz_it": True,
                "contexts": [],
                "location": {
                    "file": "myclass.cpp",
                    "line": "20",
                    "directory": "/src",
                    "fullpath": "/src/myclass.cpp",
                },
            },
        ],
        "enums": [
            {
                "name": "Color",
                "qname": "Color",
                "hash": "enum001",
                "access_type": 3,
                "enum_values": [
                    {"field_name": "RED", "value": 0},
                    {"field_name": "GREEN", "value": 1},
                    {"field_name": "BLUE", "value": 2},
                ],
            }
        ],
        "records": [
            {
                "name": "Point",
                "qname": "Point",
                "hash": "rec001",
                "is_simple": True,
                "record_type": 2,  # STRUCT_RECORD
                "access_type": 3,
                "parent_hash": "",
                "fields": [
                    {
                        "field_name": "x",
                        "field_type": "int",
                        "gen_list": [
                            {"gen_type": 0, "type_name": "int", "base_type_name": "int", "local_qualifier": "", "length": 0}
                        ],
                    },
                    {
                        "field_name": "y",
                        "field_type": "int",
                        "gen_list": [
                            {"gen_type": 0, "type_name": "int", "base_type_name": "int", "local_qualifier": "", "length": 0}
                        ],
                    },
                ],
            },
            {
                "name": "MyClass",
                "qname": "MyClass",
                "hash": "11111111",
                "is_simple": True,
                "record_type": 0,  # CLASS_RECORD
                "access_type": 0,
                "parent_hash": "",
                "fields": [],
            },
        ],
        "typedefs": [
            {
                "name": "size_type",
                "qname": "size_type",
                "type_name": "unsigned long",
                "type_source_hash": "",
                "is_builtin": True,
            }
        ],
        "compiled_files": [
            {
                "filename": "/src/test.c",
                "headers": ['"test.h"'],
                "include_paths": ["/src"],
                "compiler_opts": ["-I/src"],
            },
            {
                "filename": "/src/myclass.cpp",
                "headers": ['"myclass.h"'],
                "include_paths": ["/src"],
                "compiler_opts": ["-I/src", "-std=c++17"],
            },
        ],
    }


@pytest.fixture
def tmp_futag_package(tmp_path):
    """Create a fake futag-llvm directory structure with bin/clang placeholder."""
    futag_dir = tmp_path / "futag-llvm"
    bin_dir = futag_dir / "bin"
    bin_dir.mkdir(parents=True)

    # Create placeholder binaries
    for name in ["clang", "clang++", "llvm-config", "scan-build",
                  "intercept-build", "llvm-profdata", "llvm-cov",
                  "llvm-symbolizer"]:
        (bin_dir / name).touch()
        (bin_dir / name).chmod(0o755)

    return futag_dir.as_posix()


@pytest.fixture
def tmp_library_root(tmp_path, sample_analysis_json):
    """Create a fake library root with analysis results."""
    lib_root = tmp_path / "test-library"
    lib_root.mkdir()

    # Create required directories
    analysis_dir = lib_root / ".futag-analysis"
    analysis_dir.mkdir()
    build_dir = lib_root / ".futag-build"
    build_dir.mkdir()
    install_dir = lib_root / ".futag-install"
    install_dir.mkdir()

    # Write analysis result JSON
    analysis_file = analysis_dir / "futag-analysis-result.json"
    with open(analysis_file, "w") as f:
        json.dump(sample_analysis_json, f)

    # Create a minimal compile_commands.json
    compile_commands = [
        {
            "directory": str(lib_root / ".futag-build"),
            "command": "clang -I/src -c /src/test.c",
            "file": "/src/test.c",
        }
    ]
    with open(build_dir / "compile_commands.json", "w") as f:
        json.dump(compile_commands, f)

    return lib_root.as_posix()
