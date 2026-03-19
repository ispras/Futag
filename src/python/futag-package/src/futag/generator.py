# **************************************************
# **      ______  __  __  ______  ___     ______  **
# **     / ____/ / / / / /_  __/ /   |   / ____/  **
# **    / /_    / / / /   / /   / /| |  / / __    **
# **   / __/   / /_/ /   / /   / ___ | / /_/ /    **
# **  /_/      \____/   /_/   /_/  |_| \____/     **
# **                                              **
# **     Fuzz target Automated Generator       **
# **             a tool of ISP RAS                **
# **************************************************
# ** This module is for generating, compiling     **
# ** fuzz-drivers of functions in library         **
# **************************************************

"""Futag Generator - Standard memcpy-based fuzz target generation."""

import json
import pathlib
import copy
import os
import sys
from subprocess import Popen, PIPE
from multiprocessing import Pool
from typing import List
from distutils.dir_util import copy_tree

from futag.sysmsg import *
from futag.preprocessor import *
from futag.base_generator import BaseGenerator
from futag.generator_state import GeneratorState


class Generator(BaseGenerator):
    """Standard Futag Generator using raw memcpy buffer consumption."""

    def __init__(self, futag_llvm_package, library_root, alter_compiler="",
                 target_type=LIBFUZZER, json_file=ANALYSIS_FILE_PATH,
                 output_path=FUZZ_DRIVER_PATH, build_path=BUILD_PATH,
                 install_path=INSTALL_PATH, delimiter=".", exclude_headers=None):
        super().__init__(futag_llvm_package, library_root,
                         target_type=target_type, json_file=json_file,
                         output_path=output_path, build_path=build_path,
                         install_path=install_path, delimiter=delimiter)
        self.alter_compiler = alter_compiler
        self.exclude_headers = exclude_headers if exclude_headers else []

    @property
    def default_headers(self):
        return ["stdio.h", "stddef.h", "time.h", "stdlib.h", "string.h", "stdint.h"]

    @property
    def supports_c(self):
        return True

    @property
    def needs_buffer_check(self):
        return True

    @property
    def harness_preamble(self):
        return ""

    def _gen_builtin(self, param_name, gen_type_info):
        """Declare and assign value for a builtin type."""
        return {
            "gen_lines": [
                "//GEN_BUILTIN\n",
                gen_type_info["type_name"].replace("(anonymous namespace)::", "") + " " + param_name + ";\n",
                "memcpy(&" + param_name + ", futag_pos, sizeof(" + gen_type_info["type_name"].replace("(anonymous namespace)::", "") + "));\n",
                "futag_pos += sizeof(" + gen_type_info["type_name"].replace("(anonymous namespace)::", "") + ");\n"
            ],
            "gen_free": [],
            "buffer_size": ["sizeof(" + gen_type_info["type_name"].replace("(anonymous namespace)::", "") + ")"]
        }

    def _gen_strsize(self, param_name, param_type, dyn_size_idx, array_name):
        """Generate a string-size parameter."""
        return {
            "gen_lines": [
                "//GEN_SIZE\n",
                param_type + " " + param_name + " = (" + param_type + ") " + array_name + "[" + str(dyn_size_idx - 1) + "];\n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_cstring(self, param_name, gen_type_info, dyn_cstring_size_idx):
        """Declare and assign value for a C string type."""
        ref_name = param_name
        if gen_type_info["local_qualifier"]:
            ref_name = "r" + ref_name
        gen_lines = [
            "//GEN_CSTRING1\n",
            gen_type_info["base_type_name"] + " " + ref_name + " = (" + gen_type_info["base_type_name"] + ") malloc((dyn_cstring_size[" + str(dyn_cstring_size_idx - 1) + "] + 1)* sizeof(char));\n",
            "memset(" + ref_name + ", 0, dyn_cstring_size[" + str(dyn_cstring_size_idx - 1) + "] + 1);\n",
            "memcpy(" + ref_name + ", futag_pos, dyn_cstring_size[" + str(dyn_cstring_size_idx - 1) + "]);\n",
            "futag_pos += dyn_cstring_size[" + str(dyn_cstring_size_idx - 1) + "];\n",
        ]
        if gen_type_info["local_qualifier"]:
            gen_lines += [gen_type_info["type_name"] + " " + param_name + " = " + ref_name + ";\n"]
        return {
            "gen_lines": gen_lines,
            "gen_free": [
                "if (" + ref_name + ") {\n",
                "    free(" + ref_name + ");\n",
                "    " + ref_name + " = NULL;\n",
                "}\n"
            ],
            "buffer_size": []
        }

    def _gen_wstring(self, param_name, gen_type_info, dyn_wstring_size_idx):
        """Declare and assign value for a wide string type."""
        ref_name = param_name
        if gen_type_info["local_qualifier"]:
            ref_name = "r" + ref_name
        gen_lines = [
            "//GEN_WSTRING\n",
            gen_type_info["base_type_name"] + " " + ref_name + " = (" + gen_type_info["base_type_name"] + ") malloc((dyn_wstring_size[" + str(dyn_wstring_size_idx - 1) + "] + 1)* sizeof(wchar_t));\n",
            "memset(" + ref_name + ", 0, (dyn_wstring_size[" + str(dyn_wstring_size_idx - 1) + "] + 1)* sizeof(wchar_t));\n",
            "memcpy(" + ref_name + ", futag_pos, dyn_wstring_size[" + str(dyn_wstring_size_idx - 1) + "]* sizeof(wchar_t));\n",
            "futag_pos += dyn_wstring_size[" + str(dyn_wstring_size_idx - 1) + "]* sizeof(wchar_t);\n",
        ]
        if gen_type_info["local_qualifier"]:
            gen_lines += [gen_type_info["type_name"] + " " + param_name + " = " + ref_name + ";\n"]
        return {
            "gen_lines": gen_lines,
            "gen_free": [
                "if (" + ref_name + ") {\n",
                "    free(" + ref_name + ");\n",
                "    " + ref_name + " = NULL;\n",
                "}\n"
            ],
            "buffer_size": []
        }

    def _gen_cxxstring(self, param_name, gen_type_info, dyn_cxxstring_size_idx):
        """Declare and assign value for a C++ string type."""
        ref_name = param_name
        if gen_type_info["local_qualifier"]:
            ref_name = "r" + ref_name
        return {
            "gen_lines": [
                gen_type_info["type_name"] + " " + param_name + "(futag_pos, dyn_cxxstring_size[" + str(dyn_cxxstring_size_idx - 1) + "]); \n",
                "futag_pos += dyn_cxxstring_size[" + str(dyn_cxxstring_size_idx - 1) + "];\n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_enum(self, enum_record, param_name, gen_type_info, compiler_info, anonymous=False):
        """Declare and assign value for an enum type."""
        enum_name = gen_type_info["type_name"]
        enum_length = len(enum_record["enum_values"])
        if compiler_info["compiler"] == "CC":
            return {
                "gen_lines": [
                    "//GEN_ENUM\n",
                    "unsigned int " + param_name + "_enum_index; \n",
                    "memcpy(&" + param_name + "_enum_index, futag_pos, sizeof(unsigned int));\n",
                    enum_name + " " + param_name + " = " + param_name + "_enum_index % " + str(enum_length) + ";\n"
                ],
                "gen_free": [],
                "buffer_size": ["sizeof(unsigned int)"]
            }
        else:
            return {
                "gen_lines": [
                    "//GEN_ENUM\n",
                    "unsigned int " + param_name + "_enum_index; \n",
                    "memcpy(&" + param_name + "_enum_index, futag_pos, sizeof(unsigned int));\n",
                    enum_name + " " + param_name + " = static_cast<" + enum_name + ">(" + param_name + "_enum_index % " + str(enum_length) + ");\n"
                ],
                "gen_free": [],
                "buffer_size": ["sizeof(unsigned int)"]
            }

    def _gen_array(self, param_name, gen_type_info):
        """Declare and assign value for an array type."""
        return {
            "gen_lines": [
                "//GEN_ARRAY\n",
                gen_type_info["type_name"] + " " + param_name + " = (" + gen_type_info["type_name"] + ") malloc(sizeof(" + gen_type_info["base_type_name"] + ") * " + str(gen_type_info["length"]) + ");\n",
                "memcpy(" + param_name + ", futag_pos, " + str(gen_type_info["length"]) + " * sizeof(" + gen_type_info["base_type_name"] + "));\n",
                "futag_pos += " + str(gen_type_info["length"]) + " * sizeof(" + gen_type_info["base_type_name"] + ");\n"
            ],
            "gen_free": [
                "if (" + param_name + ") {\n",
                "    free( " + param_name + ");\n",
                "    " + param_name + " = NULL;\n",
                "}\n"
            ],
            "buffer_size": [str(gen_type_info["length"]) + " * sizeof(" + gen_type_info["base_type_name"] + ")"]
        }

    def _gen_void(self, param_name):
        """Declare and assign value for a void type."""
        return {
            "gen_lines": [
                "//GEN_VOID\n",
                "const char *" + param_name + "= NULL; \n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_qualifier(self, param_name, prev_param_name, gen_type_info):
        """Declare and assign value for a qualified type."""
        return {
            "gen_lines": [
                "//GEN_QUALIFIED\n",
                gen_type_info["type_name"] + " " + param_name + " = " + prev_param_name + ";\n"
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_pointer(self, param_name, prev_param_name, gen_type_info):
        """Declare and assign value for a pointer type."""
        return {
            "gen_lines": [
                "//GEN_POINTER\n",
                gen_type_info["type_name"].replace("(anonymous namespace)::", "") + " " + param_name + " = & " + prev_param_name + ";\n"
            ],
            "gen_free": [],
            "buffer_size": []
        }


# Backward compatibility re-exports
from futag.context_generator import ContextGenerator
from futag.natch_generator import NatchGenerator

__all__ = ["Generator", "ContextGenerator", "NatchGenerator"]
