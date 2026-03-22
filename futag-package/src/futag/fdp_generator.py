# Copyright (c) 2023-2024 ISP RAS (https://www.ispras.ru)
# Licensed under the GNU General Public License v3.0
# See LICENSE file in the project root for full license text.

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
# ** fuzz-drivers using FuzzedDataProvider API    **
# **************************************************

"""Futag FuzzedDataProvider Generator - type-safe fuzz target generation."""

from futag.sysmsg import *
from futag.base_generator import BaseGenerator


class FuzzDataProviderGenerator(BaseGenerator):
    """Generator using libFuzzer's FuzzedDataProvider API for type-safe data consumption."""

    def __init__(self, futag_llvm_package, library_root, target_type=LIBFUZZER,
                 json_file=ANALYSIS_FILE_PATH, output_path=FUZZ_DRIVER_PATH,
                 build_path=BUILD_PATH, install_path=INSTALL_PATH, delimiter=".",
                 toolchain=None) -> None:
        super().__init__(futag_llvm_package, library_root,
                         target_type=target_type, json_file=json_file,
                         output_path=output_path, build_path=build_path,
                         install_path=install_path, delimiter=delimiter,
                         toolchain=toolchain)
        self.last_string_name: str = ""

    @property
    def default_headers(self) -> list:
        """Return default headers required by FDP-based fuzz targets."""
        return ["stdio.h", "stddef.h", "time.h", "stdlib.h", "string.h",
                "stdint.h", "fuzzer/FuzzedDataProvider.h"]

    @property
    def supports_c(self) -> bool:
        """Return whether this generator supports C targets."""
        return False  # Always C++ only

    @property
    def needs_buffer_check(self) -> bool:
        """Return whether generated harnesses need a buffer size check."""
        return False

    @property
    def harness_preamble(self) -> str:
        """Return preamble code that initializes the FuzzedDataProvider."""
        return "    FuzzedDataProvider provider(Fuzz_Data, Fuzz_Size);\n"

    def _wrapper_file(self, func) -> dict:
        """Return wrapper file metadata, forcing .cpp extension for FDP targets."""
        self.target_extension = "cpp"
        return BaseGenerator._wrapper_file(self, func)

    def _gen_builtin(self, param_name, gen_type_info) -> dict:
        """Declare and assign value for a builtin type."""
        type = gen_type_info["type_name"].replace(
            "(anonymous namespace)::", "")
        if type == "double" or type == "float":
            return {
                "gen_lines": [
                    "//GEN_BUILTIN\n",
                    "auto " + param_name + " = provider.ConsumeFloatingPoint<" + type + ">();\n",
                ],
                "gen_free": [],
                "buffer_size": []
            }
        else:
            return {
                "gen_lines": [
                    "//GEN_BUILTIN\n",
                    "auto " + param_name + " = provider.ConsumeIntegral<" + type + ">();\n",
                ],
                "gen_free": [],
                "buffer_size": []
            }

    def _gen_strsize(self, param_name, param_type, dyn_size_idx, array_name) -> dict:
        """Generate a string-size parameter using last consumed string length."""
        self.last_string_name
        return {
            "gen_lines": [
                "//GEN_SIZE\n",
                param_type + " " + param_name +
                " = static_cast<" + param_type + " >(" + self.last_string_name + ".length());\n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_cstring(self, param_name, gen_type_info, dyn_cstring_size_idx) -> dict:
        """Declare and assign value for a C string type."""
        gen_lines = [
            "//GEN_CSTRING\n",
            "std::string  " + param_name + "_fdp = provider.ConsumeRandomLengthString();\n",
            gen_type_info["type_name"] + " " + param_name + " = " + param_name + "_fdp.c_str();\n",
        ]
        self.last_string_name = param_name + "_fdp"
        return {
            "gen_lines": gen_lines,
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_wstring(self, param_name, gen_type_info, dyn_wstring_size_idx) -> dict:
        """Declare and assign value for a wide string type."""
        ref_name = param_name
        if (gen_type_info["local_qualifier"]):
            ref_name = "r" + ref_name

        gen_lines = [
            "//GEN_WSTRING\n",
            "std::string  " + param_name + "_fdp = provider.ConsumeRandomLengthString();\n",
            "std::wstring widestr_" + param_name + " = std::wstring(" + param_name + "_fdp.begin(), " + param_name + "_fdp.end());\n",
            gen_type_info["type_name"] + " " + param_name + " = widestr_" + param_name + ".c_str();\n",
        ]

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

    def _gen_cxxstring(self, param_name, gen_type_info, dyn_cxxstring_size_idx) -> dict:
        """Declare and assign value for a C++ string type."""
        ref_name = param_name
        if (gen_type_info["local_qualifier"]):
            ref_name = "r" + ref_name
        gen_lines = [
            "//GEN_CXXSTRING\n",
        ]
        if (gen_type_info["local_qualifier"]):
            gen_lines += [gen_type_info["type_name"] +
                          " " + param_name + " = " + ref_name + ";\n"]

        return {
            "gen_lines": [
                "//GEN_CXXSTRING\n",
                "std::string  " + param_name + "_fdp = provider.ConsumeRandomLengthString();\n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_enum(self, enum_record, param_name, gen_type_info, compiler_info, anonymous=False) -> dict:
        """Declare and assign value for an enum type."""
        if anonymous:
            enum_name = enum_record["name"]
        else:
            enum_name = enum_record["qname"]

        enum_name = gen_type_info["type_name"]
        return {
            "gen_lines": [
                "//GEN_ENUM\n",
                "auto " + param_name + " = provider.ConsumeEnum<" + enum_name + ">()"
            ],
            "gen_free": [],
            "buffer_size": ["sizeof(unsigned int)"]
        }

    def _gen_array(self, param_name, gen_type_info) -> dict:
        """Declare and assign value for an array type."""
        return {
            "gen_lines": [
                "//GEN_ARRAY\n",
                gen_type_info["type_name"] + " " + param_name + " = (" + gen_type_info["type_name"] + ") " +
                "malloc(sizeof(" + gen_type_info["base_type_name"] +
                ") * " + str(gen_type_info["length"]) + ");\n",
                "memcpy(" + param_name + ", futag_pos, " + str(
                    gen_type_info["length"]) + " * sizeof(" + gen_type_info["base_type_name"] + "));\n",
                "futag_pos += " +
                str(gen_type_info["length"]) + " * sizeof(" +
                gen_type_info["base_type_name"] + ");\n"
            ],
            "gen_free": [
                "if (" + param_name + ") {\n",
                "    free( " + param_name + ");\n",
                "    " + param_name + " = NULL;\n",
                "}\n"
            ],
            "buffer_size": [str(gen_type_info["length"]) + " * sizeof(" + gen_type_info["base_type_name"] + ")"]
        }

    def _gen_void(self, param_name) -> dict:
        """Declare and assign value for a void type."""
        return {
            "gen_lines": [
                "//GEN_VOID\n",
                "const char *" + param_name + "= NULL; \n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_qualifier(self, param_name, prev_param_name, gen_type_info) -> dict:
        """Declare and assign value for a qualified type."""
        return {
            "gen_lines": [
                "//GEN_QUALIFIED\n",
                gen_type_info["type_name"] + " " +
                param_name + " = " + prev_param_name + ";\n"
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_pointer(self, param_name, prev_param_name, gen_type_info) -> dict:
        """Declare and assign value for a pointer type."""
        return {
            "gen_lines": [
                "//GEN_POINTER\n",
                gen_type_info["type_name"].replace("(anonymous namespace)::", "") + " " + param_name +
                " = & " + prev_param_name + ";\n"
            ],
            "gen_free": [],
            "buffer_size": []
        }
