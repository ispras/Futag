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
# ** This module is for generating fuzz-drivers   **
# ** using Natch callstack data                   **
# **************************************************

"""Futag NatchGenerator - Fuzz target generation using Natch runtime data."""

import json
import logging
import pathlib
import os
import sys

from futag.generator import Generator
from futag.sysmsg import *

logger = logging.getLogger(__name__)


class NatchGenerator(Generator):
    """Futag Generator for Natch.

    Extends Generator with Natch-specific behavior:
    - Loads Natch JSON callstack data for seed corpus generation
    - Uses Fuzz_Size_remain runtime checks in generated code
    - Iterates over target_functions parsed from Natch JSON
    """

    def __init__(self, futag_llvm_package: str, library_root: str,
                 json_file: str = "", target_type: int = LIBFUZZER,
                 output_path=FUZZ_DRIVER_PATH, build_path=BUILD_PATH,
                 install_path=INSTALL_PATH, toolchain=None):
        """Constructor of NatchGenerator class.

        Args:
            futag_llvm_package (str): path to the futag-llvm package.
            library_root (str): path to the library root.
            json_file (str): path to the JSON file from Natch.
            target_type (int, optional): format of fuzz-drivers. Defaults to LIBFUZZER.
            output_path: where to save fuzz-drivers. Defaults to FUZZ_DRIVER_PATH.
            build_path: path to the build directory. Defaults to BUILD_PATH.
            install_path: path to the install directory. Defaults to INSTALL_PATH.
        """
        # Validate Natch JSON file before calling super
        if not pathlib.Path(json_file).exists():
            sys.exit(INVALID_NATCH_JSON)

        self.natch_json_file = pathlib.Path(json_file).absolute()

        super().__init__(futag_llvm_package, library_root,
                         target_type=target_type,
                         output_path=output_path,
                         build_path=build_path,
                         install_path=install_path,
                         toolchain=toolchain)

        # Create Natch corpus directory
        Natch_corpus_path = self.output_path / "Natch_corpus"
        if not Natch_corpus_path.exists():
            Natch_corpus_path.mkdir(parents=True, exist_ok=True)
        self.Natch_corpus_path = Natch_corpus_path

        # Will be populated by parse_values()
        self.target_functions = []

    def parse_values(self):
        """Parse Natch JSON and generate seed corpus files."""
        logger.info(self.Natch_corpus_path.as_posix())
        with open(self.natch_json_file.as_posix()) as f:
            natch_values = json.load(f)
        if not natch_values:
            raise ValueError(COULD_NOT_PARSE_NATCH_CALLSTACK)
        function_name_list = set()
        target_functions = []
        for function in natch_values:
            add_arg_list = False
            if not function["Function name"] in function_name_list:
                (self.Natch_corpus_path /
                 function["Function name"]).mkdir(parents=True, exist_ok=True)
                function_name_list.add(function["Function name"])
                add_arg_list = True

            index = 0
            blob_name = "blob" + str(index)
            while ((self.Natch_corpus_path / function["Function name"] / blob_name).exists()):
                index += 1
                blob_name = "blob" + str(index)
            arguments = []
            logger.info("Parsing data of function %s", function["Function name"])
            with open((self.Natch_corpus_path / function["Function name"] / blob_name).as_posix(), "wb") as f:
                logger.info("   [*] writing seed file: %s...", (self.Natch_corpus_path /
                      function["Function name"] / blob_name).as_posix())
                for arg in function["Arguments"]:
                    arguments.append(arg["Type"])
                    if (arg["Type"] in ["char *", "const char *", "unsigned char *", "const unsigned char *", "const char *&"]):
                        f.write((len(arg["Value"])).to_bytes(
                            4, byteorder='big'))
                        f.write(arg["Value"].encode())
                    else:
                        if (not type(arg["Value"]) is int):
                            f.write(int(arg["Value"]).to_bytes(
                                8, byteorder='big'))
                        else:
                            f.write(arg["Value"].to_bytes(8, byteorder='big'))
            if add_arg_list:
                target_functions.append(
                    {
                        "name": function["Function name"],
                        "args": arguments
                    })
            self.target_functions = target_functions

    # ------------------------------------------------------------------ #
    #  Natch-specific _gen_* overrides (use Fuzz_Size_remain checks)     #
    # ------------------------------------------------------------------ #

    def _gen_builtin(self, param_name, gen_type_info):
        """Declare and assign value for a builtin type with Fuzz_Size_remain check."""
        return {
            "gen_lines": [
                "//GEN_BUILTIN\n",
                "if (Fuzz_Size_remain < sizeof(" + gen_type_info["type_name"].replace(
                    "(anonymous namespace)::", "") + ")  return 0;\n",
                "Fuzz_Size_remain = Fuzz_Size_remain - sizeof(" + gen_type_info["type_name"].replace(
                    "(anonymous namespace)::", "") + ");\n",
                gen_type_info["type_name"].replace(
                    "(anonymous namespace)::", "") + " " + param_name + ";\n",
                "memcpy(&"+param_name+", futag_pos, sizeof(" +
                gen_type_info["type_name"].replace(
                    "(anonymous namespace)::", "") + "));\n",
                "futag_pos += sizeof(" + gen_type_info["type_name"].replace(
                    "(anonymous namespace)::", "") + ");\n"
            ],
            "gen_free": [],
            "buffer_size": ["sizeof(" + gen_type_info["type_name"].replace("(anonymous namespace)::", "")+")"]
        }

    def _gen_strsize(self, param_name, param_type, dyn_size_idx, array_name):
        """Generate a string-size parameter."""
        return {
            "gen_lines": [
                "//GEN_SIZE\n",
                param_type + " " + param_name +
                " = (" + param_type +
                ") " + array_name + "[" + str(dyn_size_idx - 1) + "];\n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_cstring(self, param_name, gen_type_info, dyn_cstring_size_idx):
        """Declare and assign value for a C string type with Fuzz_Size_remain check."""
        ref_name = param_name
        if (gen_type_info["local_qualifier"]):
            ref_name = "r" + ref_name

        gen_lines = [
            "//GEN_CSTRING1\n",

            "//Read length of str\n",
            "if (Fuzz_Size_remain < sizeof(int))  return 0;\n",
            "Fuzz_Size_remain -= sizeof(int);\n",
            "int futag_str_size;\n"
            "memcpy(&futag_str_size, futag_pos, sizeof(int));\n",
            "futag_pos += sizeof(int);\n",
            "if (Fuzz_Size_remain < (size_t)futag_str_size)  return 0;\n",
            "Fuzz_Size_remain = Fuzz_Size_remain - (size_t)futag_str_size;\n",

            gen_type_info["base_type_name"] + " " + ref_name +
            " = (" + gen_type_info["base_type_name"] +
            ") malloc((futag_str_size + 1)* sizeof(char));\n",
            "memset(" + ref_name +
            ", 0, futag_str_size + 1);\n",
            "memcpy(" + ref_name +
            ", futag_pos, futag_str_size);\n",
            "futag_pos += futag_str_size;\n",
        ]
        if (gen_type_info["local_qualifier"]):
            gen_lines += [gen_type_info["type_name"] +
                          " " + param_name + " = " + ref_name + ";\n"]

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
        """Declare and assign value for a wide string type with Fuzz_Size_remain check."""
        ref_name = param_name
        if (gen_type_info["local_qualifier"]):
            ref_name = "r" + ref_name

        gen_lines = [
            "//GEN_WSTRING\n",
            "//Read length of str\n",
            "if (Fuzz_Size_remain < sizeof(int))  return 0;\n",
            "Fuzz_Size_remain -= sizeof(int);\n",
            "int futag_str_size;\n"
            "memcpy(&futag_str_size, futag_pos, sizeof(int));\n",
            "futag_pos += sizeof(int);\n",
            "if (Fuzz_Size_remain < (size_t)futag_str_size)  return 0;\n",
            "Fuzz_Size_remain = Fuzz_Size_remain - (size_t)futag_str_size;\n",

            gen_type_info["base_type_name"] + " " + ref_name +
            " = (" + gen_type_info["base_type_name"] +
            ") malloc(futag_str_size + sizeof(wchar_t));\n",
            "memset(" + ref_name +
            ", 0, (int)((futag_str_size + sizeof(wchar_t))/4));\n",
            "memcpy(" + ref_name + ", futag_pos, futag_str_size);\n",
            "futag_pos += futag_str_size;\n",
        ]
        if (gen_type_info["local_qualifier"]):
            gen_lines += [gen_type_info["type_name"] +
                          " " + param_name + " = " + ref_name + ";\n"]

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
        """Declare and assign value for a C++ string type with Fuzz_Size_remain check."""
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
                "//Read length of str\n",
                "if (Fuzz_Size_remain < sizeof(int))  return 0;\n",
                "Fuzz_Size_remain -= sizeof(int);\n",
                "int futag_str_size;\n",
                "memcpy(&futag_str_size, futag_pos, sizeof(int));\n",
                "futag_pos += sizeof(int);\n",
                "if (Fuzz_Size_remain < (size_t)futag_str_size)  return 0;\n",
                "Fuzz_Size_remain = Fuzz_Size_remain - (size_t)futag_str_size;\n",

                gen_type_info["type_name"] + " " + param_name +
                "(futag_pos, futag_str_size); \n",
                "futag_pos += futag_str_size;\n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_enum(self, enum_record, param_name, gen_type_info, compiler_info, anonymous=False):
        """Declare and assign value for an enum type."""
        if anonymous:
            enum_name = enum_record["name"]
        else:
            enum_name = enum_record["qname"]

        enum_length = len(enum_record["enum_values"])
        enum_name = gen_type_info["type_name"]
        if compiler_info["compiler"] == "CC":
            return {
                "gen_lines": [
                    "//GEN_ENUM\n",
                    "unsigned int " + param_name + "_enum_index; \n",
                    "memcpy(&" + param_name +
                    "_enum_index, futag_pos, sizeof(unsigned int));\n",
                    enum_name + " " + param_name + " = " +
                    param_name + "_enum_index % " +
                    str(enum_length) + ";\n"
                ],
                "gen_free": [],
                "buffer_size": ["sizeof(unsigned int)"]
            }
        else:
            return {
                "gen_lines": [
                    "//GEN_ENUM\n",
                    "unsigned int " + param_name + "_enum_index; \n",
                    "memcpy(&" + param_name +
                    "_enum_index, futag_pos, sizeof(unsigned int));\n",
                    enum_name + " " + param_name + " = static_cast<" + enum_name +
                    ">(" + param_name + "_enum_index % " + str(enum_length) + ");\n"
                ],
                "gen_free": [],
                "buffer_size": ["sizeof(unsigned int)"]
            }

    def _gen_array(self, param_name, gen_type_info):
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
                gen_type_info["type_name"] + " " +
                param_name + " = " + prev_param_name + ";\n"
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_pointer(self, param_name, prev_param_name, gen_type_info):
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

    # ------------------------------------------------------------------ #
    #  Natch-specific target generation methods                          #
    # ------------------------------------------------------------------ #

    def _gen_target_function(self, func, param_id) -> bool:
        """Generate a fuzz target for a function (Natch version with Fuzz_Size_remain)."""
        malloc_free = [
            "unsigned char *",
            "char *",
        ]

        if param_id == len(func['params']):
            if not self.gen_anonymous and "(anonymous namespace)" in func["qname"]:
                self.state.curr_func_log = f"This function is in anonymous namespace!"
                self.state.gen_this_function = False
            found_parent = None
            if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                # Find parent class
                for r in self.target_library["records"]:
                    if r["hash"] == func["parent_hash"]:
                        found_parent = r
                        break
                if not found_parent:
                    self.state.gen_this_function = False

            # If there is no buffer - return!
            if (not len(self.state.buffer_size) and not self.state.dyn_cstring_size_idx and not self.state.dyn_cxxstring_size_idx and not self.state.dyn_wstring_size_idx and not self.state.file_idx) or not self.state.gen_this_function:
                log = self._log_file(func, self.gen_anonymous)
                if not log:
                    logger.error(f"{CANNOT_CREATE_LOG_FILE} {func['qname']}")
                else:
                    self.state.curr_func_log = f"Log for function: {func['qname']}\n{self.state.curr_func_log}"
                    log.write(self.state.curr_func_log)
                    log.close()
                return False
            # generate file name
            wrapper_result = self._wrapper_file(func)
            logger.info("Generating fuzzing-wapper for function %s:",
                  func["qname"])
            logger.info("-- %s", wrapper_result["msg"])
            if not wrapper_result["file"]:
                self.state.gen_this_function = False
                return False
            f = wrapper_result["file"]

            f.write("//"+func["hash"] + "\n")
            for line in self._gen_header(func["location"]["fullpath"]):
                f.write(line)
            f.write('\n')
            compiler_info = self._get_compile_command(
                func["location"]["fullpath"])

            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    f.write(LIBFUZZER_PREFIX_C)
                else:
                    f.write(LIBFUZZER_PREFIX_CXX)
            else:
                f.write(AFLPLUSPLUS_PREFIX)

            f.write("    size_t Fuzz_Size_remain = Fuzz_Size;;\n")
            f.write("    uint8_t * futag_pos = Fuzz_Data;\n")
            for line in self.state.gen_lines:
                f.write("    " + line)

            if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                class_name = found_parent["qname"]
                if func["func_type"] in [FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                    f.write("    //declare the RECORD and call constructor\n")
                    f.write(
                        "    " + class_name.replace("::(anonymous namespace)", "") + " futag_target" + "(")
                else:
                    # Find default constructor
                    found_default_constructor = False
                    for fu in self.target_library["functions"]:
                        if fu["parent_hash"] == func["parent_hash"] and fu["func_type"] == FUNC_DEFAULT_CONSTRUCTOR:
                            found_default_constructor = True

                    if not found_default_constructor:
                        self.state.gen_this_function = False
                        os.unlink(f.name)
                        f.close()
                        return False
                    f.write("    //declare the RECORD first\n")
                    f.write("    " + class_name + " futag_target;\n")
                    # call the method
                    f.write("    //METHOD CALL\n")
                    f.write("    futag_target." + func["name"]+"(")
            else:
                f.write("    //FUNCTION_CALL\n")
                if func["return_type"] in malloc_free:
                    f.write("    " + func["return_type"] +
                            " futag_target = " + func["qname"] + "(")
                else:
                    f.write("    " + func["qname"] + "(")

            param_list = []
            for arg in self.state.param_list:
                param_list.append(arg + " ")
            f.write(",".join(param_list))
            f.write(");\n")
            # !attempting free on address which was not malloc()-ed

            if func["return_type"] in malloc_free:
                f.write("    if(futag_target){\n")
                f.write("        free(futag_target);\n")
                f.write("        futag_target = NULL;\n")
                f.write("    }\n")

            f.write("    //FREE\n")
            for line in self.state.gen_free:
                f.write("    " + line)
            if self.target_type == LIBFUZZER:
                f.write(LIBFUZZER_SUFFIX)
            else:
                f.write(AFLPLUSPLUS_SUFFIX)
            f.close()
            return True

        curr_param = func["params"][param_id]
        if len(curr_param["gen_list"]) > 1:
            curr_name = "_" + curr_param["param_name"]
        else:
            curr_name = curr_param["param_name"]
        prev_param_name = curr_name
        gen_curr_param = True

        curr_gen = {}
        if len(curr_param["gen_list"]) == 0:
            self.state.gen_this_function = False
            return False
        if curr_param["gen_list"][0]["gen_type"] in [GEN_BUILTIN, GEN_CSTRING, GEN_WSTRING, GEN_REFSTRING, GEN_CXXSTRING, GEN_ENUM, GEN_ARRAY, GEN_UNION, GEN_INPUT_FILE, GEN_OUTPUT_FILE, GEN_QUALIFIER, GEN_POINTER]:
            for gen_type_info in curr_param["gen_list"]:
                prev_param_name = curr_name
                if gen_type_info["gen_type"] == GEN_BUILTIN:
                    this_gen_size = False
                    if not this_gen_size:
                        curr_name = "b_" + curr_name  # builtin_prefix
                        curr_gen = self._gen_builtin(curr_name, gen_type_info)
                        self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_CSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN STRING
                        curr_name = "str_" + curr_name  # string_prefix
                        self.state.dyn_cstring_size_idx += 1
                        curr_gen = self._gen_cstring(
                            curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_REFSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN STRING
                        curr_name = "str_" + curr_name  # string_prefix
                        self.state.dyn_cstring_size_idx += 1
                        curr_gen = self._gen_cstring(
                            curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                        # curr_name = "&" + curr_name
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_WSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN STRING
                        curr_name = "str_" + curr_name  # string_prefix
                        self.state.dyn_wstring_size_idx += 1
                        curr_gen = self._gen_wstring(
                            curr_name, gen_type_info, self.state.dyn_wstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_CXXSTRING:
                    curr_name = "str_" + curr_name  # string_prefix
                    self.state.dyn_cxxstring_size_idx += 1
                    curr_gen = self._gen_cxxstring(
                        curr_name, gen_type_info, self.state.dyn_cxxstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_ENUM:  # GEN_ENUM
                    curr_name = "e_" + curr_name  # enum_prefix
                    found_enum = None
                    # search in enum list of analysis result:
                    for enum in self.target_library["enums"]:
                        if len(gen_type_info["type_name"].split(" ")) > 1:
                            if enum["qname"] == gen_type_info["type_name"].split(" ")[
                                    1]:
                                found_enum = enum
                                break
                        else:
                            if enum["qname"] == gen_type_info["type_name"]:
                                found_enum = enum
                                break
                    if not found_enum:
                        # search in typedef list of analysis result:
                        for typedef in self.target_library["typedefs"]:
                            if typedef["name"] == gen_type_info["type_name"]:
                                enum_hash = typedef["type_source_hash"]
                                for enum in self.target_library["enums"]:
                                    if enum["hash"] == enum_hash:
                                        found_enum = enum
                            break
                    if not found_enum:
                        self.state.curr_func_log += f"- Can not generate for enum: {str(gen_type_info)}\n"
                        gen_curr_param = False
                    else:
                        compiler_info = self._get_compile_command(
                            func["location"]["fullpath"])
                        curr_gen = self._gen_enum(
                            found_enum, curr_name, gen_type_info, compiler_info, self.gen_anonymous)
                        self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_UNION:
                    curr_name = "u_" + curr_name  # union_prefix
                    curr_gen = self._gen_union(curr_name, gen_type_info)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_ARRAY:  # GEN_ARRAY
                    curr_name = "a_" + curr_name  # array_prefix
                    curr_gen = self._gen_array(curr_name, gen_type_info)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_QUALIFIER:
                    curr_name = "q_" + curr_name  # qualifier_prefix
                    curr_gen = self._gen_qualifier(
                        curr_name, prev_param_name, gen_type_info)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_POINTER:
                    curr_name = "p_" + curr_name  # qualifier_prefix
                    curr_gen = self._gen_pointer(
                        curr_name, prev_param_name, gen_type_info)
                    self._append_gen_dict(curr_gen)
                prev_param_name = curr_name
            if not gen_curr_param:
                self.state.gen_this_function = False
            self.state.gen_lines += ["\n"]
            self.state.param_list += [curr_name]
            param_id += 1
            self._gen_target_function(func, param_id)

        else:
            if curr_param["gen_list"][0]["gen_type"] == GEN_STRUCT:
                curr_name = "s_" + curr_name  # struct_prefix
                result_search_return_type = self._search_return_types(
                    curr_param["gen_list"], func, self.target_library['functions'])

                if not result_search_return_type:
                    result_search_typedefs = self._search_in_typedefs(
                        curr_param["gen_list"][0]["type_name"], self.target_library['typedefs'])
                    if result_search_typedefs:
                        typedef_gen_list = [{
                            "base_type_name": result_search_typedefs["underlying_type"],
                            "gen_type": GEN_STRUCT,
                            "gen_type_name": "_STRUCT",
                            "length": 0,
                            "local_qualifier": "",
                            "type_name": result_search_typedefs["name"]
                        }]
                        result_search_typdef_return_type = self._search_return_types(
                            typedef_gen_list, func, self.target_library['functions'])
                        if result_search_typdef_return_type:
                            old_values = self.state.save()
                            for curr_return_func in result_search_typdef_return_type:
                                self.state.var_function_idx += 1
                                self.state.gen_lines += ["\n"]
                                self.state.param_list += [curr_name]
                                curr_gen = self._gen_var_function(
                                    curr_name, curr_return_func["function"])
                                self._add_header(self._get_function_header(
                                    func["location"]["fullpath"]))
                                self._append_gen_dict(curr_gen)
                                #!!!call recursive
                                param_id += 1
                                self._gen_target_function(func, param_id)
                                param_id -= 1
                                self.state.restore_from(old_values)
                        else:
                            found_struct = None
                            for record in self.target_library["records"]:
                                if len(curr_param["gen_list"][0]["type_name"].split(" ")) > 1 and record["type"] == STRUCT_RECORD and record["name"] == curr_param["gen_list"][0]["type_name"].split(" ")[1] and record["is_simple"]:
                                    found_struct = record
                                    break
                            if found_struct:
                                curr_gen = self._gen_struct(
                                    curr_name, record, curr_param["gen_list"][0])
                                self._append_gen_dict(curr_gen)
                            else:
                                _tmp = curr_param["gen_list"][0]
                                self.state.curr_func_log += f"- Could not generate for object: {str(_tmp)}. Could not find function call to generate this struct!\n"
                        gen_curr_param = False
                    else:
                        _tmp = curr_param["gen_list"][0]
                        self.state.curr_func_log += f"- Could not generate for object: {str(_tmp)}. Could not create function call to generate this struct, and the definition of struct not found!\n"
                        gen_curr_param = False
                else:
                    old_values = self.state.save()
                    for curr_return_func in result_search_return_type:
                        self.state.var_function_idx += 1
                        self.state.gen_lines += ["\n"]
                        self.state.param_list += [curr_name]
                        curr_gen = self._gen_var_function(
                            curr_name, curr_return_func["function"])
                        self._add_header(self._get_function_header(
                            func["location"]["fullpath"]))
                        self._append_gen_dict(curr_gen)
                        #!!!call recursive
                        param_id += 1
                        self._gen_target_function(func, param_id)
                        param_id -= 1
                        self.state.restore_from(old_values)

            if curr_param["gen_list"][0]["gen_type"] == GEN_CLASS:
                curr_name = "c_" + curr_name  # struct_prefix
                result_search_return_type = self._search_return_types(
                    curr_param["gen_list"], func, self.target_library['functions'])

                if not result_search_return_type:
                    found_class = None
                    for record in self.target_library["records"]:
                        if record["type"] == CLASS_RECORD and record["name"] == curr_param["gen_list"][0]["type_name"]:
                            found_class = record
                            break
                    if found_class:
                        curr_gen_list = self._gen_class(
                            curr_name, found_class)
                        old_values = self.state.save()
                        for curr_gen in curr_gen_list:
                            self._append_gen_dict(curr_gen)
                            #!!!call recursive
                            self.state.gen_lines += ["\n"]
                            self.state.param_list += [curr_name]
                            param_id += 1
                            self.state.var_function_idx += 1
                            self._gen_target_function(func, param_id)
                            param_id -= 1
                            self.state.restore_from(old_values)
                    else:
                        gen_type_info = curr_param["gen_list"][0]
                        self.state.curr_func_log += f"- Could not generate for object: {str(gen_type_info)}. Could not find function call to generate this class!\n"
                        gen_curr_param = False
                else:
                    old_values = self.state.save()
                    for curr_return_func in result_search_return_type:
                        self.state.var_function_idx += 1
                        self.state.gen_lines += ["\n"]
                        self.state.param_list += [curr_name]
                        curr_gen = self._gen_var_function(
                            curr_name, curr_return_func["function"])
                        self._add_header(self._get_function_header(
                            func["location"]["fullpath"]))
                        self._append_gen_dict(curr_gen)
                        #!!!call recursive
                        param_id += 1
                        self._gen_target_function(func, param_id)
                        param_id -= 1
                        self.state.restore_from(old_values)

            if curr_param["gen_list"][0]["gen_type"] in [GEN_INCOMPLETE, GEN_VOID, GEN_FUNCTION, GEN_UNKNOWN]:
                gen_type_info = curr_param["gen_list"][0]
                self.state.curr_func_log += f"- Can not generate for object: {str(gen_type_info)}\n"
                gen_curr_param = False

            if not gen_curr_param:
                self.state.gen_this_function = False
            self.state.gen_lines += ["\n"]
            self.state.param_list += [curr_name]
            param_id += 1
            self._gen_target_function(func, param_id)

    def _gen_anonymous_function(self, func, param_id) -> bool:
        """Generate an anonymous fuzz target (Natch version with Fuzz_Size_remain)."""
        malloc_free = [
            "unsigned char *",
            "char *",
            "wchar_t *"
        ]
        if param_id == len(func['params']):
            found_parent = None
            if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                # Find parent class
                for r in self.target_library["records"]:
                    if r["hash"] == func["parent_hash"]:
                        found_parent = r
                        break
                if not found_parent:
                    self.state.gen_this_function = False

            # If there is no buffer - return!
            if (not len(self.state.buffer_size) and not self.state.dyn_cstring_size_idx and not self.state.dyn_cxxstring_size_idx and not self.state.dyn_wstring_size_idx and not self.state.file_idx) or not self.state.gen_this_function:
                log = self._log_file(func, self.gen_anonymous)
                if not log:
                    logger.error(f"{CANNOT_CREATE_LOG_FILE} {func['qname']}")
                else:
                    self.state.curr_func_log = f"Log for function: {func['qname']}\n{self.state.curr_func_log}"
                    log.write(self.state.curr_func_log)
                    log.close()
                return False
            # generate file name
            f = self._anonymous_wrapper_file(func)
            if not f:
                self.state.gen_this_function = False
                logger.error(f"{CANNOT_CREATE_WRAPPER_FILE} {func['qname']}")
                return False
            logger.info(f"{WRAPPER_FILE_CREATED} {f.name}")

            for line in self._gen_header(func["location"]["fullpath"]):
                f.write("// " + line)
            f.write('\n')
            compiler_info = self._get_compile_command(
                func["location"]["fullpath"])

            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    f.write(LIBFUZZER_PREFIX_C)
                else:
                    f.write(LIBFUZZER_PREFIX_CXX)
            else:
                f.write(AFLPLUSPLUS_PREFIX)

            f.write("    size_t Fuzz_Size_remain = Fuzz_Size;\n")
            f.write("    uint8_t * futag_pos = Fuzz_Data;\n")
            for line in self.state.gen_lines:
                f.write("    " + line)

            f.write("    //" + func["qname"])

            if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                class_name = found_parent["qname"]
                if func["func_type"] in [FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                    f.write("    //declare the RECORD and call constructor\n")
                    f.write(
                        "    " + class_name.replace("::(anonymous namespace)", "") + " futag_target" + "(")
                else:
                    # Find default constructor
                    found_default_constructor = False
                    for fu in self.target_library["functions"]:
                        if fu["parent_hash"] == func["parent_hash"] and fu["func_type"] == FUNC_DEFAULT_CONSTRUCTOR:
                            found_default_constructor = True

                    if not found_default_constructor:
                        self.state.gen_this_function = False
                        os.unlink(f.name)
                        f.close()
                        return False
                    f.write("    //declare the RECORD first\n")
                    f.write(
                        "    " + class_name.replace("::(anonymous namespace)", "") + " futag_target;\n")
                    # call the method
                    f.write("    //METHOD CALL\n")
                    f.write("    futag_target." + func["name"]+"(")
            else:
                f.write("    //FUNCTION_CALL\n")
                if func["return_type"] in malloc_free:
                    f.write("    " + func["return_type"] +
                            " futag_target = " + func["qname"] + "(")
                else:
                    f.write(
                        "    " + func["qname"].replace("::(anonymous namespace)", "") + "(")

            param_list = []
            for arg in self.state.param_list:
                param_list.append(arg + " ")
            f.write(",".join(param_list))
            f.write(");\n")
            # !attempting free on address which was not malloc()-ed

            if func["return_type"] in malloc_free:
                f.write("    if(futag_target){\n")
                f.write("        free(futag_target);\n")
                f.write("        futag_target = NULL;\n")
                f.write("    }\n")

            f.write("    //FREE\n")
            for line in self.state.gen_free:
                f.write("    " + line)
            if self.target_type == LIBFUZZER:
                f.write(LIBFUZZER_SUFFIX)
            else:
                f.write(AFLPLUSPLUS_SUFFIX)
            f.close()
            return True

        curr_param = func["params"][param_id]
        if len(curr_param["gen_list"]) > 1:
            curr_name = "_" + curr_param["param_name"]
        else:
            curr_name = curr_param["param_name"]
        prev_param_name = curr_name
        gen_curr_param = True

        curr_gen = {}
        if len(curr_param["gen_list"]) == 0:
            self.state.gen_this_function = False
            return False
        if curr_param["gen_list"][0]["gen_type"] in [GEN_BUILTIN, GEN_CSTRING, GEN_WSTRING, GEN_REFSTRING, GEN_CXXSTRING, GEN_ENUM, GEN_ARRAY, GEN_UNION, GEN_INPUT_FILE, GEN_OUTPUT_FILE, GEN_QUALIFIER, GEN_POINTER]:
            for gen_type_info in curr_param["gen_list"]:
                prev_param_name = curr_name
                if gen_type_info["gen_type"] == GEN_BUILTIN:
                    this_gen_size = False
                    if not this_gen_size:
                        curr_name = "b_" + curr_name  # builtin_prefix
                        curr_gen = self._gen_builtin(curr_name, gen_type_info)
                        self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_CSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN STRING
                        curr_name = "str_" + curr_name  # string_prefix
                        self.state.dyn_cstring_size_idx += 1
                        curr_gen = self._gen_cstring(
                            curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_REFSTRING:
                    logger.debug("!!!GEN_REFSTRING")
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN_REFSTRING
                        curr_name = "str_" + curr_name  # string_prefix
                        self.state.dyn_cstring_size_idx += 1
                        curr_gen = self._gen_cstring(
                            curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                        # curr_name = "&" + curr_name
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_WSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN STRING
                        curr_name = "str_" + curr_name  # string_prefix
                        self.state.dyn_wstring_size_idx += 1
                        curr_gen = self._gen_wstring(
                            curr_name, gen_type_info, self.state.dyn_wstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_CXXSTRING:
                    curr_name = "str_" + curr_name  # string_prefix
                    self.state.dyn_cxxstring_size_idx += 1
                    curr_gen = self._gen_cxxstring(
                        curr_name, gen_type_info, self.state.dyn_cxxstring_size_idx)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_ENUM:  # GEN_ENUM
                    curr_name = "e_" + curr_name  # enum_prefix
                    found_enum = None
                    # search in enum list of analysis result:
                    for enum in self.target_library["enums"]:
                        if len(gen_type_info["type_name"].split(" ")) > 1:
                            if enum["qname"] == gen_type_info["type_name"].split(" ")[
                                    1]:
                                found_enum = enum
                                break
                        else:
                            if enum["qname"] == gen_type_info["type_name"]:
                                found_enum = enum
                                break
                    if not found_enum:
                        # search in typedef list of analysis result:
                        for typedef in self.target_library["typedefs"]:
                            if typedef["name"] == gen_type_info["type_name"]:
                                enum_hash = typedef["type_source_hash"]
                                for enum in self.target_library["enums"]:
                                    if enum["hash"] == enum_hash:
                                        found_enum = enum
                            break
                    if not found_enum:
                        self.state.curr_func_log += f"- Can not generate for enum: {str(gen_type_info)}\n"
                        gen_curr_param = False
                    else:
                        compiler_info = self._get_compile_command(
                            func["location"]["fullpath"])
                        curr_gen = self._gen_enum(
                            found_enum, curr_name, gen_type_info, compiler_info, self.gen_anonymous)
                        self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_UNION:
                    curr_name = "u_" + curr_name  # union_prefix
                    curr_gen = self._gen_union(curr_name, gen_type_info)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_ARRAY:  # GEN_ARRAY
                    curr_name = "a_" + curr_name  # array_prefix
                    curr_gen = self._gen_array(curr_name, gen_type_info)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_QUALIFIER:
                    curr_name = "q_" + curr_name  # qualifier_prefix
                    curr_gen = self._gen_qualifier(
                        curr_name, prev_param_name, gen_type_info)
                    self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_POINTER:
                    curr_name = "p_" + curr_name  # qualifier_prefix
                    curr_gen = self._gen_pointer(
                        curr_name, prev_param_name, gen_type_info)
                    self._append_gen_dict(curr_gen)
                prev_param_name = curr_name
            if not gen_curr_param:
                self.state.gen_this_function = False
            self.state.gen_lines += ["\n"]
            self.state.param_list += [curr_name]
            param_id += 1
            self._gen_anonymous_function(func, param_id)

        else:
            if curr_param["gen_list"][0]["gen_type"] == GEN_STRUCT:
                curr_name = "s_" + curr_name  # struct_prefix
                result_search_return_type = self._search_return_types(
                    curr_param["gen_list"], func, self.target_library['functions'])

                if not result_search_return_type:
                    result_search_typedefs = self._search_in_typedefs(
                        curr_param["gen_list"][0]["type_name"], self.target_library['typedefs'])
                    if result_search_typedefs:
                        typedef_gen_list = [{
                            "base_type_name": result_search_typedefs["underlying_type"],
                            "gen_type": GEN_STRUCT,
                            "gen_type_name": "_STRUCT",
                            "length": 0,
                            "local_qualifier": "",
                            "type_name": result_search_typedefs["name"]
                        }]
                        result_search_typdef_return_type = self._search_return_types(
                            typedef_gen_list, func, self.target_library['functions'])
                        if result_search_typdef_return_type:
                            old_values = self.state.save()
                            for curr_return_func in result_search_typdef_return_type:
                                self.state.var_function_idx += 1
                                self.state.gen_lines += ["\n"]
                                self.state.param_list += [curr_name]
                                curr_gen = self._gen_var_function(
                                    curr_name, curr_return_func["function"])
                                self._add_header(self._get_function_header(
                                    func["location"]["fullpath"]))
                                self._append_gen_dict(curr_gen)
                                #!!!call recursive
                                param_id += 1
                                self._gen_anonymous_function(func, param_id)
                                param_id -= 1
                                self.state.restore_from(old_values)
                        else:
                            found_struct = None
                            for record in self.target_library["records"]:
                                if len(curr_param["gen_list"][0]["type_name"].split(" ")) > 1 and record["type"] == STRUCT_RECORD and record["name"] == curr_param["gen_list"][0]["type_name"].split(" ")[1] and record["is_simple"]:
                                    found_struct = record
                                    break
                            if found_struct:
                                curr_gen = self._gen_struct(
                                    curr_name, record, curr_param["gen_list"][0])
                                self._append_gen_dict(curr_gen)
                            else:
                                _tmp = curr_param["gen_list"][0]
                                self.state.curr_func_log += f"- Could not generate for object: {str(_tmp)}. Could not find function call to generate this struct!\n"
                        gen_curr_param = False
                    else:
                        _tmp = curr_param["gen_list"][0]
                        self.state.curr_func_log += f"- Could not generate for object: {str(_tmp)}. Could not create function call to generate this struct, and the definition of struct not found!\n"
                        gen_curr_param = False
                else:
                    old_values = self.state.save()
                    for curr_return_func in result_search_return_type:
                        self.state.var_function_idx += 1
                        self.state.gen_lines += ["\n"]
                        self.state.param_list += [curr_name]
                        curr_gen = self._gen_var_function(
                            curr_name, curr_return_func["function"])
                        self._add_header(self._get_function_header(
                            func["location"]["fullpath"]))
                        self._append_gen_dict(curr_gen)
                        #!!!call recursive
                        param_id += 1
                        self._gen_anonymous_function(func, param_id)
                        param_id -= 1
                        self.state.restore_from(old_values)

            if curr_param["gen_list"][0]["gen_type"] == GEN_CLASS:
                curr_name = "c_" + curr_name  # struct_prefix
                result_search_return_type = self._search_return_types(
                    curr_param["gen_list"], func, self.target_library['functions'])

                if not result_search_return_type:
                    found_class = None
                    for record in self.target_library["records"]:
                        if record["type"] == CLASS_RECORD and record["name"] == curr_param["gen_list"][0]["type_name"]:
                            found_class = record
                            break
                    if found_class:
                        curr_gen_list = self._gen_class(
                            curr_name, found_class)
                        old_values = self.state.save()
                        for curr_gen in curr_gen_list:
                            self._append_gen_dict(curr_gen)
                            #!!!call recursive
                            self.state.gen_lines += ["\n"]
                            self.state.param_list += [curr_name]
                            param_id += 1
                            self.state.var_function_idx += 1
                            self._gen_anonymous_function(func, param_id)
                            param_id -= 1
                            self.state.restore_from(old_values)
                    else:
                        gen_type_info = curr_param["gen_list"][0]
                        self.state.curr_func_log += f"- Could not generate for object: {str(gen_type_info)}. Could not find function call to generate this class!\n"
                        gen_curr_param = False
                else:
                    old_values = self.state.save()
                    for curr_return_func in result_search_return_type:
                        self.state.var_function_idx += 1
                        self.state.gen_lines += ["\n"]
                        self.state.param_list += [curr_name]
                        curr_gen = self._gen_var_function(
                            curr_name, curr_return_func["function"])
                        self._add_header(self._get_function_header(
                            func["location"]["fullpath"]))
                        self._append_gen_dict(curr_gen)
                        #!!!call recursive
                        param_id += 1
                        self._gen_anonymous_function(func, param_id)
                        param_id -= 1
                        self.state.restore_from(old_values)

            if curr_param["gen_list"][0]["gen_type"] in [GEN_INCOMPLETE, GEN_VOID, GEN_FUNCTION, GEN_UNKNOWN]:
                gen_type_info = curr_param["gen_list"][0]
                self.state.curr_func_log += f"- Can not generate for object: {str(gen_type_info)}\n"
                gen_curr_param = False

            if not gen_curr_param:
                self.state.gen_this_function = False
            self.state.gen_lines += ["\n"]
            self.state.param_list += [curr_name]
            param_id += 1
            self._gen_anonymous_function(func, param_id)

    # ------------------------------------------------------------------ #
    #  Natch-specific gen_targets (iterates over self.target_functions)   #
    # ------------------------------------------------------------------ #

    def gen_targets(self, anonymous=False, max_wrappers=10):
        """Generate fuzz targets for functions identified by Natch.

        Parameters
        ----------
        anonymous: bool
            option for generating fuzz-targets of non-public functions, default to False.
        max_wrappers: int
            maximum number of wrapper variants per function.
        """
        self.gen_anonymous = anonymous
        self.max_wrappers = max_wrappers
        C_generated_function = []
        C_unknown_function = []
        Cplusplus_usual_class_method = []
        Cplusplus_static_class_method = []
        Cplusplus_anonymous_class_method = []
        for target in self.target_functions:
            for func in self.target_library["functions"]:
                if target["name"] != func["name"]:
                    continue
                # For C
                if func["access_type"] == AS_NONE and func["fuzz_it"] and func["storage_class"] < 2 and (func["parent_hash"] == ""):
                    logger.info("Try to generate fuzz-driver for function: %s...", func["name"])
                    C_generated_function.append(func["name"])
                    self.state.gen_this_function = True
                    self.state.header = []
                    self.state.buffer_size = []
                    self.state.gen_lines = []
                    self.state.gen_free = []
                    self.state.dyn_cstring_size_idx = 0
                    self.state.dyn_wstring_size_idx = 0
                    self.state.dyn_cxxstring_size_idx = 0
                    self.state.file_idx = 0
                    self.state.var_function_idx = 0
                    self.state.param_list = []
                    self.state.curr_function = func
                    self.state.curr_func_log = ""
                    if "(anonymous" in func["qname"]:
                        self._gen_anonymous_function(func, 0)
                    else:
                        self._gen_target_function(func, 0)

                # For C++, Declare object of class and then call the method
                if func["access_type"] == AS_PUBLIC and func["fuzz_it"] and func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR, FUNC_GLOBAL, FUNC_STATIC] and (not "::operator" in func["qname"]):
                    Cplusplus_usual_class_method.append(func["qname"])
                    logger.info("Try to generate fuzz-driver for class method: %s...", func["name"])
                    self.state.gen_this_function = True
                    self.state.header = []
                    self.state.buffer_size = []
                    self.state.gen_lines = []
                    self.state.gen_free = []
                    self.state.dyn_cstring_size_idx = 0
                    self.state.dyn_wstring_size_idx = 0
                    self.state.dyn_cxxstring_size_idx = 0
                    self.state.file_idx = 0
                    self.state.var_function_idx = 0
                    self.state.param_list = []
                    self.state.curr_function = func
                    self.state.curr_func_log = ""
                    if "(anonymous" in func["qname"]:
                        self._gen_anonymous_function(func, 0)
                    else:
                        self._gen_target_function(func, 0)

                # For C++, Call the static function of class without declaring object
                if func["access_type"] in [AS_NONE, AS_PUBLIC] and func["fuzz_it"] and func["func_type"] in [FUNC_CXXMETHOD, FUNC_GLOBAL, FUNC_STATIC] and func["storage_class"] == SC_STATIC:
                    self.state.gen_this_function = True
                    self.state.header = []
                    self.state.buffer_size = []
                    self.state.gen_lines = []
                    self.state.gen_free = []
                    self.state.dyn_cstring_size_idx = 0
                    self.state.dyn_wstring_size_idx = 0
                    self.state.dyn_cxxstring_size_idx = 0
                    self.state.file_idx = 0
                    self.state.var_function_idx = 0
                    self.state.param_list = []
                    self.state.curr_function = func
                    self.state.curr_func_log = ""
                    if (not "(anonymous namespace)" in func["qname"]) and (not "::operator" in func["qname"]):
                        Cplusplus_static_class_method.append(func["qname"])
                    if "(anonymous" in func["qname"]:
                        self._gen_anonymous_function(func, 0)

                # We dont generate for static function of C
                if func["func_type"] == FUNC_UNKNOW_RECORD and func["storage_class"] == 2:
                    C_unknown_function.append(func["qname"])

            self.result_report = {
                "C_generated_functions": C_generated_function,
                "Cplusplus_static_class_methods": Cplusplus_static_class_method,
                "Cplusplus_usual_class_methods": Cplusplus_usual_class_method,
                "Cplusplus_anonymous_class_methods": Cplusplus_anonymous_class_method,
                "C_unknown_functions": C_unknown_function
            }
            with open((self.build_path / "result-report.json").as_posix(), "w") as f:
                json.dump(self.result_report, f)

    def gen_targets_from_callstack(self, target):
        """Generate fuzz targets from a specific Natch callstack entry.

        Args:
            target: dict with at least a "qname" key identifying the function.
        """
        found_function = None
        for func in self.target_library["functions"]:
            if func["qname"] == target["qname"]:
                found_function = func
                self._gen_target_function(func, 0)
        if not found_function:
            sys.exit("Function \"%s\" not found in library!" % target["qname"])
