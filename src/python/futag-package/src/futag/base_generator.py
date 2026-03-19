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
# ** This module provides the BaseGenerator ABC   **
# ** with shared logic for generating, compiling  **
# ** fuzz-drivers of functions in library         **
# **************************************************

import json
import pathlib
import copy
import os
import sys
from abc import ABC, abstractmethod
from subprocess import Popen, PIPE
from multiprocessing import Pool
from typing import List
from distutils.dir_util import copy_tree

from futag.sysmsg import *
from futag.preprocessor import delete_folder
from futag.generator_state import GeneratorState


class BaseGenerator(ABC):
    """Abstract base class for Futag fuzz target generators.

    Contains all shared infrastructure logic extracted from Generator.
    Subclasses must implement the 10 abstract type-specific generation methods.
    """

    # ------------------------------------------------------------------ #
    #  Subclass configuration properties                                  #
    # ------------------------------------------------------------------ #

    @property
    def default_headers(self):
        """Default C headers to include in every fuzz target."""
        return ["stdio.h", "stddef.h", "time.h",
                "stdlib.h", "string.h", "stdint.h"]

    @property
    def supports_c(self):
        """Whether this generator supports C targets."""
        return True

    @property
    def needs_buffer_check(self):
        """Whether generated targets need a buffer size check."""
        return True

    @property
    def harness_preamble(self):
        """Optional preamble code inserted before harness body."""
        return ""

    # ------------------------------------------------------------------ #
    #  Abstract methods -- subclasses MUST implement these                #
    # ------------------------------------------------------------------ #

    @abstractmethod
    def _gen_builtin(self, param_name, gen_type_info) -> dict:
        """Declare and assign value for a builtin type."""
        ...

    @abstractmethod
    def _gen_strsize(self, param_name, param_type, dyn_size_idx, array_name) -> dict:
        """Generate a string-size parameter."""
        ...

    @abstractmethod
    def _gen_cstring(self, param_name, gen_type_info, dyn_cstring_size_idx) -> dict:
        """Declare and assign value for a C string type."""
        ...

    @abstractmethod
    def _gen_wstring(self, param_name, gen_type_info, dyn_wstring_size_idx) -> dict:
        """Declare and assign value for a wide string type."""
        ...

    @abstractmethod
    def _gen_cxxstring(self, param_name, gen_type_info, dyn_cxxstring_size_idx) -> dict:
        """Declare and assign value for a C++ string type."""
        ...

    @abstractmethod
    def _gen_enum(self, enum_record, param_name, gen_type_info, compiler_info, anonymous=False) -> dict:
        """Declare and assign value for an enum type."""
        ...

    @abstractmethod
    def _gen_array(self, param_name, gen_type_info) -> dict:
        """Declare and assign value for an array type."""
        ...

    @abstractmethod
    def _gen_void(self, param_name) -> dict:
        """Declare and assign value for a void type."""
        ...

    @abstractmethod
    def _gen_qualifier(self, param_name, prev_param_name, gen_type_info) -> dict:
        """Declare and assign value for a qualified type."""
        ...

    @abstractmethod
    def _gen_pointer(self, param_name, prev_param_name, gen_type_info) -> dict:
        """Declare and assign value for a pointer type."""
        ...

    # ------------------------------------------------------------------ #
    #  Constructor                                                        #
    # ------------------------------------------------------------------ #

    def __init__(self, futag_llvm_package: str, library_root: str, target_type: int = LIBFUZZER, json_file: str = ANALYSIS_FILE_PATH, output_path=FUZZ_DRIVER_PATH, build_path=BUILD_PATH, install_path=INSTALL_PATH, delimiter: str = "."):
        """ Constructor of BaseGenerator class.

        Args:
            futag_llvm_package (str): path to the futag-llvm package (with binaries, scripts, etc.).
            library_root (str): path to the library root.
            target_type (int, optional): format of fuzz-drivers (LIBFUZZER or AFLPLUSPLUS). Defaults to LIBFUZZER.
            json_file (str, optional): path to the futag-analysis-result.json file. Defaults to ANALYSIS_FILE_PATH.
            output_path (_type_, optional): where to save fuzz-drivers, if this path exists, Futag will delete it and create new one. Defaults to FUZZ_DRIVER_PATH.
            build_path (_type_, optional): path to the build directory. Defaults to BUILD_PATH.
            install_path (_type_, optional): path to the install directory. Defaults to INSTALL_PATH.

        Raises:
            ValueError: INVALID_TARGET_TYPE: Invalid the type of target.
            ValueError: INVALID_FUTAG_PATH: Invalid path of futag-llvm.
            ValueError: INVALID_LIBPATH: Invalid path of library.
            ValueError: INVALID_ANALYSIS_FILE: Invalid path to analysis result file.
            ValueError: INVALID_BUILPATH: Invalid path to the library build path.
            ValueError: INVALID_INSTALLPATH: Invalid path to the library install path.
        """

        self.output_path = None  # Path for saving fuzzing drivers
        self.tmp_output_path = None  # Path for saving fuzzing drivers
        self.json_file = json_file
        self.futag_llvm_package = futag_llvm_package
        self.library_root = library_root
        self.target_library = None
        self.exclude_headers = []
        self.alter_compiler = ""
        self.gen_anonymous = False
        self.max_wrappers = 10
        self.delimiter = delimiter

        # Mutable generation state managed by GeneratorState
        self.state = GeneratorState()

        # save the list of generated function for debugging
        self.target_extension = ""
        self.result_report = {}

        if (target_type > 1 or target_type < 0):
            sys.exit(INVALID_TARGET_TYPE)

        self.target_type = target_type

        if pathlib.Path(self.futag_llvm_package).exists():
            self.futag_llvm_package = pathlib.Path(
                self.futag_llvm_package).absolute()
        else:
            sys.exit(INVALID_FUTAG_PATH)

        if self.target_type == LIBFUZZER:
            if not pathlib.Path(self.futag_llvm_package / "bin/clang").exists():
                sys.exit(INVALID_FUTAG_PATH)
        else:
            if not pathlib.Path(self.futag_llvm_package / "AFLplusplus/usr/local/bin/afl-clang-fast").exists():
                sys.exit(INVALID_FUTAG_PATH)

        if pathlib.Path(self.library_root).exists():
            self.library_root = pathlib.Path(self.library_root).absolute()
        else:
            sys.exit(INVALID_LIBPATH)

        if not pathlib.Path(json_file).exists():
            self.json_file = self.library_root / ANALYSIS_FILE_PATH
        else:
            self.json_file = pathlib.Path(json_file)

        if self.json_file.exists():
            f = open(self.json_file.as_posix())
            if not f.closed:
                self.target_library = json.load(f)
            tmp_output_path = "." + output_path
            # create directory for function targets if not exists
            # TODO: set option for deleting

            # if (self.library_root / output_path).exists():
            #     delete_folder(self.library_root / output_path)
            # if (self.library_root / tmp_output_path).exists():
            #     delete_folder(self.library_root / tmp_output_path)

            simple_functions = []
            if self.target_library["functions"]:
                for f_iter in self.target_library["functions"]:
                    if f_iter["is_simple"]:
                        simple_functions.append(f_iter)
            self.simple_functions = simple_functions
            (self.library_root / output_path).mkdir(parents=True, exist_ok=True)
            (self.library_root / tmp_output_path).mkdir(parents=True, exist_ok=True)
            self.output_path = (self.library_root / output_path).absolute()
            self.tmp_output_path = (
                self.library_root / tmp_output_path).absolute()

            succeeded_path = self.output_path / "succeeded"
            if not succeeded_path.exists():
                (succeeded_path).mkdir(parents=True, exist_ok=True)
            self.succeeded_path = succeeded_path

            failed_path = self.output_path / "failed"
            if not failed_path.exists():
                (failed_path).mkdir(parents=True, exist_ok=True)
            self.failed_path = failed_path
        else:
            sys.exit(INVALID_ANALYSIS_FILE)

        if not (self.library_root / build_path).exists():
            sys.exit(INVALID_BUILPATH)
        self.build_path = self.library_root / build_path

        if not (self.library_root / install_path).exists():
            sys.exit(INVALID_INSTALLPATH)
        self.install_path = self.library_root / install_path

    # ------------------------------------------------------------------ #
    #  Helper: check if a parameter is a file parameter                   #
    # ------------------------------------------------------------------ #

    def _is_file_param(self, param):
        """Check whether a parameter represents a file path/descriptor.

        Args:
            param (dict): parameter dict from analysis JSON.

        Returns:
            bool: True if the parameter looks like a file parameter.
        """
        return (param.get("param_usage") in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"]
                or param.get("param_name", "") in ["filename", "file", "filepath"]
                or "file" in param.get("param_name", "").lower()
                or "File" in param.get("param_name", ""))

    # ------------------------------------------------------------------ #
    #  Infrastructure methods                                             #
    # ------------------------------------------------------------------ #

    def _get_compile_command(self, file):
        """ Get the compile command of given file

        Args:
            file (FILE): given file

        Returns:
            dict(compiler, command, file, location): dict consists of compiler type, compile command, file name, and file location.
        """
        if (self.build_path / "compile_commands.json").exists():
            compile_commands = self.build_path / "compile_commands.json"
            commands = json.load(open(compile_commands.as_posix()))
            for command in commands:
                if pathlib.Path(command["file"]) == pathlib.Path(file):
                    extension = command["file"].split(".")[-1]
                    if extension == "c":
                        return {
                            "compiler": "CC",
                            "command": command["command"],
                            "file": command["file"],
                            "location": command["directory"]
                        }
                    else:
                        return {
                            "compiler": "CXX",
                            "command": command["command"],
                            "file": command["file"],
                            "location": command["directory"]
                        }
        if file.split(".")[-1] == "c":
            return {
                "compiler": "CC",
                "command": "",
                "file": file,
                "location": ""
            }
        else:
            return {
                "compiler": "CXX",
                "command": "",
                "file": file,
                "location": ""
            }

    def _gen_header(self, target_function_name):
        """ Generate header for the target function

        Args:
            target_function_name (string): the target function name.

        Returns:
            list: list of included header.
        """

        defaults = self.default_headers
        compiled_files = self.target_library["compiled_files"]
        included_headers = []
        found = False
        for f in compiled_files:
            if f["filename"] == target_function_name:
                found = True
                for header in f["headers"]:
                    if not header[1:-1] in defaults:
                        included_headers.append(header)
                break
        if not found:
            short_filename = target_function_name.split('/')[-1]
            for f in compiled_files:
                if f["filename"].split('/')[-1] == short_filename:
                    found = True
                    for header in f["headers"]:
                        if not header[1:-1] in defaults:
                            included_headers.append(header)
                    break

        if self.exclude_headers:
            for h in self.exclude_headers:
                if h in included_headers:
                    included_headers.remove(h)
                if h in self.state.header:
                    self.state.header.remove(h)

        include_lines = []
        for i in defaults:
            include_lines.append("#include <" + i + ">\n")
        for i in included_headers:
            include_lines.append("#include " + i + "\n")
        if self.state.header:
            for i in self.state.header:
                if i not in included_headers:
                    include_lines.append("#include " + i + "\n")
        return include_lines

    def _get_function_header(self, func_location):
        """ Generate header for the target function

        Args:
            func_location (string): function location.

        Returns:
            list: list of included header.
        """
        defaults = self.default_headers
        compiled_files = self.target_library["compiled_files"]
        included_headers = []
        found = False
        for f in compiled_files:
            if f["filename"] == func_location:
                found = True
                for header in f["headers"]:
                    if not header[1:-1] in defaults:
                        included_headers.append(header)
                break
        if not found:
            short_filename = func_location.split('/')[-1]
            for f in compiled_files:
                if f["filename"].split('/')[-1] == short_filename:
                    found = True
                    for header in f["headers"]:
                        if not header[1:-1] in defaults:
                            included_headers.append(header)
                    break
        return included_headers

    def _add_header(self, function_headers):
        for h in function_headers:
            if h not in self.state.header:
                self.state.header.append(h)

    def _search_in_typedefs(self, type_name, typedefs):
        # Are there multiple type definitions for the same data type???
        result = None
        for td in typedefs:
            if td["underlying_type"] == type_name:
                return td
        return result

    def _search_return_types(self, param_gen_list, curr_function, function_lists):
        result = []
        for f in function_lists:
            gen_list = []
            # To avoid infinite loop, we search only function with different name
            if f["qname"] == curr_function["qname"]:
                continue
            # Search only simple function with the same return type

            compiler_info = self._get_compile_command(
                curr_function["location"]["fullpath"])
            compiler = compiler_info["compiler"]

            if f["gen_return_type"] and f["gen_return_type"][0]["type_name"] == param_gen_list[0]["type_name"] and f["is_simple"]:
                if (compiler != "CXX" and f["storage_class"] != SC_STATIC) or (compiler == "CXX" and not f["access_type"] in [AS_PROTECTED, AS_PRIVATE]):
                    f_gen_list_length = len(f["gen_return_type"])
                    param_gen_list_length = len(param_gen_list)
                    min_length = f_gen_list_length if f_gen_list_length < param_gen_list_length else param_gen_list_length
                    iter = 0
                    while iter < min_length and f["gen_return_type"][iter]["type_name"] == param_gen_list[iter]["type_name"]:
                        iter += 1

                    last_iter = iter
                    while iter < f_gen_list_length:
                        curr_gen_field = f["gen_return_type"][iter]
                        if curr_gen_field["gen_type"] == GEN_POINTER:
                            # curr_gen_field["gen_type"] = GEN_VARADDR
                            curr_gen_field["gen_type_name"] = "_VAR_ADDRESS"
                        else:
                            curr_gen_field["gen_type"] == GEN_UNKNOWN

                        gen_list.append(curr_gen_field)
                        iter += 1

                    iter = last_iter
                    while iter < param_gen_list_length:
                        gen_list.append(param_gen_list[iter])
                        iter += 1

                    result.append({
                        "function": f,
                        "gen_list": gen_list,
                    })
        return result

    def _append_gen_dict(self, curr_gen):
        if curr_gen:
            self.state.buffer_size += curr_gen["buffer_size"]
            self.state.gen_lines += curr_gen["gen_lines"]
            self.state.gen_free += curr_gen["gen_free"]

    # ------------------------------------------------------------------ #
    #  Complex shared generation methods                                  #
    # ------------------------------------------------------------------ #

    def _gen_struct(self, struct_name, struct, gen_info):
        gen_lines = [gen_info["type_name"] + " " + struct_name + ";\n"]
        gen_free = []
        buffer_size = []
        field_id = 0

        for field in struct["fields"]:
            curr_name = field["field_name"]
            for gen_type_info in field["gen_list"]:
                this_gen_size = False
                if gen_type_info["gen_type"] == GEN_BUILTIN:
                    if field_id > 0 and (struct["fields"][field_id - 1]["gen_list"][0]["gen_type"] in [GEN_CSTRING, GEN_WSTRING, GEN_CXXSTRING]):
                        if gen_type_info["type_name"] in ["size_t", "unsigned char", "char", "int", "unsigned", "unsigned int", "short", "unsigned short", "short int", "unsigned short int"]:
                            dyn_size_idx = 0
                            array_name = ""
                            if struct["fields"][field_id - 1]["gen_list"][0]["gen_type"] == GEN_CSTRING:
                                dyn_size_idx = self.state.dyn_cstring_size_idx
                                array_name = "dyn_cstring_size"
                            elif struct["fields"][field_id - 1]["gen_list"][0]["gen_type"] == GEN_WSTRING:
                                dyn_size_idx = self.state.dyn_wstring_size_idx
                                array_name = "dyn_wstring_size"
                            else:
                                dyn_size_idx = self.state.dyn_cxxstring_size_idx
                                array_name = "dyn_cxxstring_size"
                            curr_name = "sz_" + curr_name  # size_prefix
                            curr_gen = self._gen_strsize(
                                curr_name, gen_type_info["type_name"], dyn_size_idx, array_name)
                            buffer_size += curr_gen["buffer_size"]
                            gen_lines += curr_gen["gen_lines"]
                            gen_free += curr_gen["gen_free"]
                            this_gen_size = True  # with break, we may not need this variable :)
                            break

                    if not this_gen_size:
                        curr_name = "b_" + curr_name  # builtin_prefix
                        curr_gen = self._gen_builtin(curr_name, gen_type_info)
                        buffer_size += curr_gen["buffer_size"]
                        gen_lines += curr_gen["gen_lines"]
                        gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_CSTRING:
                    curr_name = "strc_" + curr_name  # string_prefix
                    self.state.dyn_cstring_size_idx += 1
                    curr_gen = self._gen_cstring(
                        curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_REFSTRING:
                    curr_name = "strc_" + curr_name  # string_prefix
                    self.state.dyn_cstring_size_idx += 1
                    curr_gen = self._gen_cstring(
                        curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                    # reinit value of curr_name to send reference of string
                    # curr_name = "&" + curr_name  # string_prefix
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_WSTRING:
                    curr_name = "strc_" + curr_name  # string_prefix
                    self.state.dyn_wstring_size_idx += 1
                    curr_gen = self._gen_wstring(
                        curr_name, gen_type_info, self.state.dyn_wstring_size_idx)
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_CXXSTRING:
                    curr_name = "strcxx_" + curr_name  # string_prefix
                    self.state.dyn_cxxstring_size_idx += 1
                    curr_gen = self._gen_cxxstring(
                        curr_name, gen_type_info, self.state.dyn_cxxstring_size_idx)
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

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
                        self.state.curr_func_log += f"- Can not generate for object: {str(gen_type_info)}\n"
                        self.state.gen_this_function = False
                    else:
                        compiler_info = self._get_compile_command(
                            self.state.curr_function["location"]["fullpath"])
                        curr_gen = self._gen_enum(
                            found_enum, curr_name, gen_type_info, compiler_info, self.gen_anonymous)
                        buffer_size += curr_gen["buffer_size"]
                        gen_lines += curr_gen["gen_lines"]
                        gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_ARRAY:  # GEN_ARRAY
                    curr_name = "a_" + curr_name  # array_prefix
                    curr_gen = self._gen_array(curr_name, gen_type_info)
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_QUALIFIER:
                    curr_name = "q_" + curr_name  # qualifier_prefix
                    curr_gen = self._gen_qualifier(
                        curr_name, prev_param_name, gen_type_info)
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_POINTER:
                    curr_name = "p_" + curr_name  # pointer_prefix
                    curr_gen = self._gen_pointer(
                        curr_name, prev_param_name, gen_type_info)
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

                prev_param_name = curr_name
            gen_lines += [struct_name + "." +
                          field["field_name"] + " = " + curr_name + ";\n"]
            field_id += 1

        return {
            "gen_lines": gen_lines,
            "gen_free": gen_free,
            "buffer_size": buffer_size
        }

    def _gen_union(self, param_name, gen_type_info):
        """Declare and assign value for a union type

        Args:
            param_name (str): _description_
            gen_type_info (dict): information of parameter's type for initializing

        Returns:
            dict: (gen_lines, gen_free, buffer_size)
        """
        return {
            "gen_lines": [
                "//GEN_UNION\n",
                gen_type_info["type_name"] + " " + param_name + ";\n",
                "memcpy(&"+param_name+", futag_pos, sizeof(" +
                gen_type_info["type_name"] + "));\n",
                "futag_pos += sizeof(" + gen_type_info["type_name"] + ");\n"
            ],
            "gen_free": [],
            "buffer_size": ["sizeof(" + gen_type_info["type_name"] + ")"]
        }

    def _gen_class(self, param_name, class_record):
        """Declare and assign value for a class type

        Args:
            param_name (str): _description_
            gen_type_info (dict): information of parameter's type for initializing

        Returns:
            dict: (gen_lines, gen_free, buffer_size)
        """
        result = []
        constructors = [c for c in self.target_library["functions"] if c['parent_hash'] == class_record['hash']
                        and c['is_simple'] and c["func_type"] in [FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]]

        # if class has default constructor, then return this constructor
        for c in constructors:
            if c['is_simple'] and c["func_type"] == FUNC_DEFAULT_CONSTRUCTOR:
                result.append(self._gen_var_function(param_name, c))

        return result

    def _gen_input_file(self, param_name, gen_type_info):
        cur_gen_free = ["    " + x for x in self.state.gen_free]
        if gen_type_info["gen_type"] == GEN_CSTRING:
            line = "const char* " + param_name + \
                " = \"futag_input_file_" + str(self.state.file_idx - 1) + "\";\n"
        elif gen_type_info["gen_type"] == GEN_WSTRING:
            line = "const wchar_t * " + param_name + \
                " = L\"futag_input_file_" + str(self.state.file_idx - 1) + "\";\n"
        else:
            return {
                "gen_lines": [],
                "gen_free": [],
                "buffer_size": []
            }
        gen_lines = [
            "//GEN_INPUT_FILE\n",
            line,
            "FILE * fp_" + str(self.state.file_idx - 1) +
            " = fopen(" + param_name + ",\"w\");\n",
            "if (fp_" + str(self.state.file_idx - 1) + "  == NULL) {\n",
        ]
        gen_lines += cur_gen_free
        gen_lines += [
            "    return 0;\n",
            "}\n",
            "fwrite(futag_pos, 1, file_size[" + str(self.state.file_idx - 1) +
            "], fp_" + str(self.state.file_idx - 1) + ");\n",
            "fclose(fp_" + str(self.state.file_idx - 1) + ");\n",
            "futag_pos += file_size[" + str(self.state.file_idx - 1) + "];\n"
        ]
        return {
            "gen_lines": gen_lines,
            "gen_free": [],
            "buffer_size": []
        }

    def _gen_file_descriptor(self, param_name, gen_type_info):
        if not "<fcntl.h>" in self.state.header:
            self.state.header += ["<fcntl.h>"]
        cur_gen_free = ["    " + x for x in self.state.gen_free]
        gen_lines = [
            "//GEN_FILE_DESCRIPTOR\n",
            "const char* " + param_name + "_tmp" + str(self.state.file_idx) + " = \"futag_input_file_" +
            str(self.state.file_idx - 1) + "\";\n",
            "FILE * fp_" + str(self.state.file_idx - 1) +
            " = fopen(" + param_name + "_tmp" +
            str(self.state.file_idx) + ",\"w\");\n",
            "if (fp_" + str(self.state.file_idx - 1) + "  == NULL) {\n",
        ]
        gen_lines += cur_gen_free
        gen_lines += [
            "    return 0;\n",
            "}\n",
            "fwrite(futag_pos, 1, file_size[" + str(self.state.file_idx - 1) +
            "], fp_" + str(self.state.file_idx - 1) + ");\n",
            "fclose(fp_" + str(self.state.file_idx - 1) + ");\n",
            "futag_pos += file_size[" + str(self.state.file_idx - 1) + "];\n",
            gen_type_info["type_name"] + " " + param_name +
            "= open(" + param_name + "_tmp" +
            str(self.state.file_idx) + ", O_RDWR);\n"
        ]
        gen_free = ["close(" + param_name + ");\n"]
        return {
            "gen_lines": gen_lines,
            "gen_free": gen_free,
            "buffer_size": []
        }

    def _gen_var_function(self, func_param_name: str, func):
        """ Initialize for argument of function call """
        # curr_dyn_size = 0
        param_list = []
        curr_gen_string = -1
        gen_dict = {
            "gen_lines": [],
            "gen_free": [],
            "buffer_size": [],
        }
        if not self.gen_anonymous and "(anonymous namespace)" in func["qname"]:
            self.state.gen_this_function = False
            return gen_dict
        param_id = 0
        for arg in func["params"]:
            if len(arg["gen_list"]) > 1:
                curr_name = "_" + str(self.state.var_function_idx) + \
                    "_" + arg["param_name"]
            else:
                curr_name = curr_name = str(
                    self.state.var_function_idx) + "_" + arg["param_name"]
            prev_param_name = curr_name
            for gen_type_info in arg["gen_list"]:
                if gen_type_info["gen_type"] == GEN_BUILTIN:
                    this_gen_size = False
                    if arg["param_usage"] in ["FILE_DESCRIPTOR"]:
                        curr_name = "fd_" + curr_name + \
                            str(self.state.file_idx)  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_file_descriptor(
                            curr_name, gen_type_info)
                        gen_dict["buffer_size"] += curr_gen["buffer_size"]
                        gen_dict["gen_lines"] += curr_gen["gen_lines"]
                        gen_dict["gen_free"] += curr_gen["gen_free"]
                        break
                    elif param_id > 0 and (func["params"][param_id - 1]["gen_list"][0]["gen_type"] in [GEN_CSTRING, GEN_WSTRING, GEN_CXXSTRING] or arg["param_usage"] == "SIZE_FIELD"):
                        if gen_type_info["type_name"] in ["size_t", "unsigned char", "char", "int", "unsigned", "unsigned int", "short", "unsigned short", "short int", "unsigned short int"]:
                            dyn_size_idx = 0
                            array_name = ""
                            if func["params"][param_id - 1]["gen_list"][0]["gen_type"] == GEN_CSTRING:
                                dyn_size_idx = self.state.dyn_cstring_size_idx
                                array_name = "dyn_cstring_size"
                            elif func["params"][param_id - 1]["gen_list"][0]["gen_type"] == GEN_WSTRING:
                                dyn_size_idx = self.state.dyn_wstring_size_idx
                                array_name = "dyn_wstring_size"
                            else:
                                dyn_size_idx = self.state.dyn_cxxstring_size_idx
                                array_name = "dyn_cxxstring_size"
                            curr_name = "sz_" + curr_name  # size_prefix
                            curr_gen = self._gen_strsize(
                                curr_name, arg["param_type"], dyn_size_idx, array_name)
                            gen_dict["buffer_size"] += curr_gen["buffer_size"]
                            gen_dict["gen_lines"] += curr_gen["gen_lines"]
                            gen_dict["gen_free"] += curr_gen["gen_free"]
                            this_gen_size = True  # with break, we may not need this variable :)
                            break
                    if not this_gen_size:
                        curr_name = "b_" + curr_name  # builtin_prefix
                        curr_gen = self._gen_builtin(curr_name, gen_type_info)
                        gen_dict["buffer_size"] += curr_gen["buffer_size"]
                        gen_dict["gen_lines"] += curr_gen["gen_lines"]
                        gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_CSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (arg["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or arg["param_name"] in ["filename", "file", "filepath"] or arg["param_name"].find('file') != -1 or arg["param_name"].find('File') != -1) and len(arg["gen_list"]) == 1:
                        curr_name = "f_" + curr_name + \
                            str(self.state.file_idx)  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        curr_name = "str_" + curr_name + \
                            str(self.state.dyn_cstring_size_idx)  # string_prefix
                        self.state.dyn_cstring_size_idx += 1
                        curr_gen = self._gen_cstring(
                            curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_REFSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (arg["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or arg["param_name"] in ["filename", "file", "filepath"] or arg["param_name"].find('file') != -1 or arg["param_name"].find('File') != -1) and len(arg["gen_list"]) == 1:
                        curr_name = "f_" + curr_name + \
                            str(self.state.file_idx)  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        curr_name = "str_" + curr_name + \
                            str(self.state.dyn_cstring_size_idx)  # string_prefix
                        self.state.dyn_cstring_size_idx += 1
                        curr_gen = self._gen_cstring(
                            curr_name, gen_type_info, self.state.dyn_cstring_size_idx)
                        # curr_name = "&" + curr_name
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_WSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (arg["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or arg["param_name"] in ["filename", "file", "filepath"] or arg["param_name"].find('file') != -1 or arg["param_name"].find('File') != -1) and len(arg["gen_list"]) == 1:
                        curr_name = "f_" + curr_name + \
                            str(self.state.file_idx)  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        curr_name = "str_" + curr_name + \
                            str(self.state.dyn_wstring_size_idx)  # string_prefix
                        self.state.dyn_wstring_size_idx += 1
                        curr_gen = self._gen_wstring(
                            curr_name, gen_type_info, self.state.dyn_wstring_size_idx)
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_CXXSTRING:

                    if (arg["param_name"] in ["filename", "file", "filepath", "path"] or arg["param_name"].find('file') != -1 or arg["param_name"].find('File') != -1 or arg["param_name"].find('path') != -1) and len(arg["gen_list"]) == 1:
                        curr_name = "f_" + curr_name + \
                            str(self.state.file_idx)  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_input_file(
                            curr_name, gen_type_info)
                    else:

                        curr_name = "str_" + curr_name + \
                            str(self.state.dyn_cxxstring_size_idx)  # string_prefix
                        self.state.dyn_cxxstring_size_idx += 1
                        curr_gen = self._gen_cxxstring(
                            curr_name, gen_type_info, self.state.dyn_cxxstring_size_idx)
                        gen_dict["buffer_size"] += curr_gen["buffer_size"]
                        gen_dict["gen_lines"] += curr_gen["gen_lines"]
                        gen_dict["gen_free"] += curr_gen["gen_free"]

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
                        self.state.gen_this_function = False
                    else:
                        compiler_info = self._get_compile_command(
                            func["location"]["fullpath"])
                        curr_gen = self._gen_enum(
                            found_enum, curr_name, gen_type_info, compiler_info, self.gen_anonymous)
                        gen_dict["buffer_size"] += curr_gen["buffer_size"]
                        gen_dict["gen_lines"] += curr_gen["gen_lines"]
                        gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_ARRAY:  # GEN_ARRAY
                    curr_name = "a_" + curr_name  # array_prefix
                    curr_gen = self._gen_array(curr_name, gen_type_info)
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_VOID:
                    curr_name = "a_" + curr_name  # void_prefix
                    self.state.curr_func_log += f"- Can not generate for object of void type: {str(gen_type_info)}\n"
                    self.state.gen_this_function = False

                if gen_type_info["gen_type"] == GEN_QUALIFIER:
                    curr_name = "q_" + curr_name  # qualifier_prefix
                    curr_gen = self._gen_qualifier(
                        curr_name, prev_param_name, gen_type_info)
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_POINTER:
                    curr_name = "p_" + curr_name  # qualifier_prefix
                    curr_gen = self._gen_pointer(
                        curr_name, prev_param_name, gen_type_info)
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]
                prev_param_name = curr_name

            param_id += 1
            param_list.append(curr_name)

        found_parent = None
        if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
            # Find parent class
            for r in self.target_library["records"]:
                if r["hash"] == func["parent_hash"]:
                    found_parent = r
                    break
            if not found_parent:
                self.state.gen_this_function = False
            class_name = found_parent["qname"]
            if func["func_type"] in [FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                function_call = "    //declare the RECORD and call constructor\n"
                function_call += "    " + class_name.replace(
                    "::(anonymous namespace)", "") + func_param_name + "(" + ",".join(param_list)+");\n"
            else:
                # Find default constructor
                # TODO: add code for other constructors
                found_default_constructor = False
                for fu in self.target_library["functions"]:
                    if fu["parent_hash"] == func["parent_hash"] and fu["func_type"] == FUNC_DEFAULT_CONSTRUCTOR:
                        found_default_constructor = True

                # TODO: add code for other constructors!!!
                if not found_default_constructor:
                    self.state.gen_this_function = False
                function_call = "    //declare the RECORD first\n"
                function_call += "    " + \
                    class_name.replace(
                        "::(anonymous namespace)", "") + " " + func_param_name + ";\n"
                # call the method
                function_call += "    //METHOD CALL\n"
                function_call += "    " + func_param_name + "." + \
                    func["name"]+"(" + ",".join(param_list)+");\n"

        else:
            function_call = "//GEN_VAR_FUNCTION\n    " + func["return_type"] + " " + func_param_name + \
                " = " + func["qname"] + \
                "(" + ",".join(param_list)+");\n"

        gen_dict["gen_lines"] += [function_call]
        return gen_dict

    # ------------------------------------------------------------------ #
    #  File management methods                                            #
    # ------------------------------------------------------------------ #

    def _wrapper_file(self, func):

        # if anonymous:
        #     filename = func["name"]
        #     filepath = self.tmp_output_path / "anonymous"
        # else:
        filename = func["qname"].replace(":", "_")
        filepath = self.tmp_output_path

        self.target_extension = func["location"]["fullpath"].split(".")[-1]
        file_index = 1

        # qname = func["qname"]
        if len(filename) > 250:
            return {
                "file": None,
                "msg": "Error: File name is too long (>250 characters)!"
            }
        dir_name = filename + self.delimiter + str(file_index)

        if not (filepath / filename).exists():
            (filepath / filename).mkdir(parents=True, exist_ok=True)

        # Each variant of fuzz-driver will be save in separated directory
        # inside the directory of function

        while (filepath / filename / dir_name).exists():
            file_index += 1
            dir_name = filename + self.delimiter + str(file_index)
            if file_index > self.max_wrappers:
                break

        if file_index > self.max_wrappers:
            return {
                "file": None,
                "msg": "Warning: exeeded maximum number of generated fuzzing-wrappers for each function!"
            }
        (filepath / filename / dir_name).mkdir(parents=True, exist_ok=True)

        file_name = filename + self.delimiter + \
            str(file_index) + "." + self.target_extension

        full_path = (filepath / filename / dir_name / file_name).as_posix()
        f = open(full_path, 'w')
        if f.closed:
            return {
                "file": None,
                "msg": "Error: File closed!"
            }
        return {
            "file": f,
            "msg": "Successed: " + full_path + " created!"
        }

    def _anonymous_wrapper_file(self, func):

        # if anonymous:
        #     filename = func["name"]
        #     filepath = self.tmp_output_path / "anonymous"
        # else:
        source_path = func["location"]["fullpath"]
        filename = "anonymous_" + func["name"].replace(":", "_")
        filepath = self.tmp_output_path

        self.target_extension = func["location"]["fullpath"].split(".")[-1]
        file_index = 1

        # qname = func["qname"]
        if len(filename) > 250:
            return None
        dir_name = filename + str(file_index)

        if not (filepath / filename).exists():
            (filepath / filename).mkdir(parents=True, exist_ok=True)

        # Each variant of fuzz-driver will be save in separated directory
        # inside the directory of function

        while (filepath / filename / dir_name).exists():
            file_index += 1
            dir_name = filename + str(file_index)
            if file_index > self.max_wrappers:
                break

        if file_index > self.max_wrappers:
            return None
        (filepath / filename / dir_name).mkdir(parents=True, exist_ok=True)

        file_name = filename + \
            str(file_index) + "." + self.target_extension

        full_path_destination = (
            filepath / filename / dir_name / file_name).as_posix()
        with open(source_path, 'r') as s:
            source_file = s.read()
            d = open(full_path_destination, "w")
            d.write("//"+func["hash"] + "\n")
            d.write(source_file)
            d.close()
        f = open(full_path_destination, 'a')
        if f.closed:
            return None
        return f

    def _log_file(self, func, anonymous: bool = False):
        if anonymous:
            filename = func["name"]
            filepath = self.tmp_output_path / "anonymous"
        else:
            filename = func["qname"]
            filepath = self.tmp_output_path

        file_index = 1

        # qname = func["qname"]
        if len(filename) > 250:
            print("Error: File name is too long (>250 characters)!")
            return None
        dir_name = filename + str(file_index)

        if not (filepath / filename).exists():
            (filepath / filename).mkdir(parents=True, exist_ok=True)

        # Each variant of fuzz-driver will be save in separated directory
        # inside the directory of function

        while (filepath / filename / dir_name).exists():
            file_index += 1
            dir_name = filename + str(file_index)
            if file_index > self.max_wrappers:
                break

        if file_index > self.max_wrappers:
            print("Warning: exeeded maximum number of generated fuzzing-wrappers for each function!")
            return None
        (filepath / filename / dir_name).mkdir(parents=True, exist_ok=True)

        file_name = filename + str(file_index) + ".log"

        full_path = (filepath / filename / dir_name / file_name).as_posix()
        f = open(full_path, 'w')
        if f.closed:
            print("crreate file error: ", full_path)
            return None
        return f

    # ------------------------------------------------------------------ #
    #  State save/restore                                                 #
    # ------------------------------------------------------------------ #

    def _save_state(self):
        """Save the current generation state for later restoration."""
        return self.state.save()

    def _restore_state(self, saved_state):
        """Restore generation state from a previously saved copy."""
        self.state.restore_from(saved_state)

    # ------------------------------------------------------------------ #
    #  _gen_target_function -- merged from __gen_target_function and      #
    #  __gen_anonymous_function                                           #
    # ------------------------------------------------------------------ #

    def _gen_target_function(self, func, param_id, anonymous=False) -> bool:
        malloc_free = [
            "unsigned char *",
            "char *",
        ]
        if anonymous:
            malloc_free.append("wchar_t *")

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
                    print(CANNOT_CREATE_LOG_FILE, func["qname"])
                    if not anonymous:
                        return False
                else:
                    self.state.curr_func_log = f"Log for function: {func['qname']}\n{self.state.curr_func_log}"
                    log.write(self.state.curr_func_log)
                    log.close()
                return False

            if anonymous:
                # generate file name (anonymous path)
                f = self._anonymous_wrapper_file(func)
                if not f:
                    self.state.gen_this_function = False
                    print(CANNOT_CREATE_WRAPPER_FILE, func["qname"])
                    return False
                print(WRAPPER_FILE_CREATED, f.name)

                for line in self._gen_header(func["location"]["fullpath"]):
                    f.write("// " + line)
                f.write('\n')
            else:
                # generate file name (normal path)
                wrapper_result = self._wrapper_file(func)
                print("Generating fuzzing-wapper for function ",
                      func["qname"], ": ")
                print("-- ", wrapper_result["msg"])
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

            if anonymous:
                # Anonymous buffer check (old style)
                buffer_check = str(self.state.dyn_wstring_size_idx) + "*sizeof(wchar_t) + " + str(self.state.dyn_cxxstring_size_idx) + \
                    "*sizeof(char) + " + str(self.state.dyn_cstring_size_idx) + \
                    " + " + str(self.state.file_idx)
                if self.state.buffer_size:
                    buffer_check += " + " + " + ".join(self.state.buffer_size)
                f.write("    if (Fuzz_Size < " + buffer_check + ") return 0;\n")
            else:
                # Normal buffer check (new style)
                buffer_check_list = []
                wchar_t_check = ""
                if self.state.dyn_wstring_size_idx > 0:
                    wchar_t_check = str(self.state.dyn_wstring_size_idx) + " * sizeof(wchar_t)"
                    buffer_check_list.append(wchar_t_check)
                dyn_cstring_check = ""
                if self.state.dyn_cstring_size_idx > 0:
                    dyn_cstring_check = str(self.state.dyn_cstring_size_idx) + " * sizeof(char)"
                    buffer_check_list.append(dyn_cstring_check)
                file_idx_check = ""
                if self.state.file_idx > 0:
                    file_idx_check = str(self.state.file_idx)
                    buffer_check_list.append(file_idx_check)

                buffer_check = ""
                if self.state.buffer_size:
                    if buffer_check_list:
                        buffer_check = "+".join(buffer_check_list) + " + " + " + ".join(self.state.buffer_size)
                    else:
                        buffer_check = " + ".join(self.state.buffer_size)
                else:
                    buffer_check = "+".join(buffer_check_list)

                f.write("    if (Fuzz_Size < " + buffer_check + ") return 0;\n")

            if self.state.dyn_cstring_size_idx > 0:
                if anonymous:
                    f.write(
                        "    size_t dyn_cstring_buffer = (size_t) ((Fuzz_Size + sizeof(char) - (" + buffer_check + " )));\n")
                else:
                    f.write(
                        "    size_t dyn_cstring_buffer = (size_t) (Fuzz_Size + " + str(self.state.dyn_cstring_size_idx) + "*sizeof(char) - (" + buffer_check + " ));\n")
                f.write("    //generate random array of dynamic string sizes\n")
                f.write("    size_t dyn_cstring_size[" +
                        str(self.state.dyn_cstring_size_idx) + "];\n")
                if self.state.dyn_cstring_size_idx > 1:
                    f.write("    srand(time(NULL));\n")
                    f.write(
                        "    if(dyn_cstring_buffer == 0) dyn_cstring_size[0] = dyn_cstring_buffer; \n")
                    f.write(
                        "    else dyn_cstring_size[0] = rand() % dyn_cstring_buffer; \n")
                    f.write("    size_t remain = dyn_cstring_size[0];\n")
                    f.write("    for(size_t i = 1; i< " +
                            str(self.state.dyn_cstring_size_idx) + " - 1; i++){\n")
                    f.write(
                        "        if(dyn_cstring_buffer - remain == 0) dyn_cstring_size[i] = dyn_cstring_buffer - remain;\n")
                    f.write(
                        "        else dyn_cstring_size[i] = rand() % (dyn_cstring_buffer - remain);\n")
                    f.write("        remain += dyn_cstring_size[i];\n")
                    f.write("    }\n")
                    f.write(
                        "    dyn_cstring_size[" + str(self.state.dyn_cstring_size_idx) + " - 1] = dyn_cstring_buffer - remain;\n")
                else:
                    f.write("    dyn_cstring_size[0] = dyn_cstring_buffer;\n")
                f.write(
                    "    //end of generation random array of dynamic string sizes\n")

            if self.state.dyn_wstring_size_idx > 0:
                if anonymous:
                    f.write("    size_t dyn_wstring_buffer = (size_t) ((Fuzz_Size + sizeof(wchar_t) - (" +
                            buffer_check + " )))/sizeof(wchar_t);\n")
                else:
                    f.write("    size_t dyn_wstring_buffer = (size_t) (Fuzz_Size + " + str(self.state.dyn_wstring_size_idx) + "*sizeof(wchar_t) - (" +
                            buffer_check + " ))/sizeof(wchar_t);\n")
                f.write("    //generate random array of dynamic string sizes\n")
                f.write("    size_t dyn_wstring_size[" +
                        str(self.state.dyn_wstring_size_idx) + "];\n")
                if self.state.dyn_wstring_size_idx > 1:
                    f.write("    srand(time(NULL));\n")
                    f.write(
                        "    if(dyn_wstring_buffer == 0) dyn_wstring_size[0] = dyn_wstring_buffer; \n")
                    f.write(
                        "    else dyn_wstring_size[0] = rand() % dyn_wstring_buffer; \n")
                    f.write("    size_t remain = dyn_wstring_size[0];\n")
                    f.write("    for(size_t i = 1; i< " +
                            str(self.state.dyn_wstring_size_idx) + " - 1; i++){\n")
                    f.write(
                        "        if(dyn_wstring_buffer - remain == 0) dyn_wstring_size[i] = dyn_wstring_buffer - remain;\n")
                    f.write(
                        "        else dyn_wstring_size[i] = rand() % (dyn_wstring_buffer - remain);\n")
                    f.write("        remain += dyn_wstring_size[i];\n")
                    f.write("    }\n")
                    f.write(
                        "    dyn_wstring_size[" + str(self.state.dyn_wstring_size_idx) + " - 1] = dyn_wstring_buffer - remain;\n")
                else:
                    f.write("    dyn_wstring_size[0] = dyn_wstring_buffer;\n")
                f.write(
                    "    //end of generation random array of dynamic string sizes\n")

            if self.state.dyn_cxxstring_size_idx > 0:
                if anonymous:
                    f.write(
                        "    size_t dyn_cxxstring_buffer = (size_t) ((Fuzz_Size + sizeof(char) - (" + buffer_check + " )));\n")
                else:
                    f.write(
                        "    size_t dyn_cxxstring_buffer = (size_t) (Fuzz_Size  - (" + buffer_check + " ));\n")
                f.write("    //generate random array of dynamic string sizes\n")
                f.write("    size_t dyn_cxxstring_size[" +
                        str(self.state.dyn_cxxstring_size_idx) + "];\n")
                if self.state.dyn_cxxstring_size_idx > 1:
                    f.write("    srand(time(NULL));\n")
                    f.write(
                        "    if(dyn_cxxstring_buffer == 0) dyn_cxxstring_size[0] = dyn_cxxstring_buffer; \n")
                    f.write(
                        "    else dyn_cxxstring_size[0] = rand() % dyn_cxxstring_buffer; \n")
                    f.write("    size_t remain = dyn_cxxstring_size[0];\n")
                    f.write("    for(size_t i = 1; i< " +
                            str(self.state.dyn_cxxstring_size_idx) + " - 1; i++){\n")
                    f.write(
                        "        if(dyn_cxxstring_buffer - remain == 0) dyn_cxxstring_size[i] = dyn_cxxstring_buffer - remain;\n")
                    f.write(
                        "        else dyn_cxxstring_size[i] = rand() % (dyn_cxxstring_buffer - remain);\n")
                    f.write("        remain += dyn_cxxstring_size[i];\n")
                    f.write("    }\n")
                    f.write(
                        "    dyn_cxxstring_size[" + str(self.state.dyn_cxxstring_size_idx) + " - 1] = dyn_cxxstring_buffer - remain;\n")
                else:
                    f.write(
                        "    dyn_cxxstring_size[0] = dyn_cxxstring_buffer;\n")
                f.write(
                    "    //end of generation random array of dynamic string sizes\n")

            if self.state.file_idx > 0:
                if anonymous:
                    f.write("    size_t file_buffer = (size_t) ((Fuzz_Size + " +
                            str(self.state.file_idx) + " - (" + buffer_check + " )));\n")
                else:
                    f.write("    size_t file_buffer = (size_t) (Fuzz_Size + " +
                            str(self.state.file_idx) + " - (" + buffer_check + " ));\n")
                f.write("    //generate random array of dynamic file sizes\n")
                f.write("    size_t file_size[" +
                        str(self.state.file_idx) + "];\n")
                if self.state.file_idx > 1:
                    f.write("    srand(time(NULL));\n")
                    f.write(
                        "    if(file_buffer == 0) file_size[0] = file_buffer;\n")
                    f.write("    else file_size[0] = rand() % file_buffer;\n")
                    f.write("    size_t remain = file_size[0];\n")
                    f.write("    for(size_t i = 1; i< " +
                            str(self.state.file_idx) + " - 1; i++){\n")
                    f.write(
                        "        if(file_buffer - remain == 0) file_size[i] = file_buffer - remain;\n")
                    f.write(
                        "        else file_size[i] = rand() % (file_buffer - remain);\n")
                    f.write("        remain += file_size[i];\n")
                    f.write("    }\n")
                    f.write(
                        "    file_size[" + str(self.state.file_idx) + " - 1] = file_buffer - remain;\n")
                else:
                    f.write("    file_size[0] = file_buffer;\n")
                f.write(
                    "    //end of generation random array of dynamic file sizes\n")

            f.write("    uint8_t * futag_pos = Fuzz_Data;\n")
            for line in self.state.gen_lines:
                f.write("    " + line)

            if anonymous:
                f.write("    //" + func["qname"])
            # else: no comment line in normal mode

            if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                class_name = found_parent["qname"]
                if func["func_type"] in [FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                    f.write("    //declare the RECORD and call constructor\n")
                    f.write(
                        "    " + class_name.replace("::(anonymous namespace)", "") + " futag_target" + "(")
                else:
                    # Find default constructor
                    # TODO: add code for other constructors
                    found_default_constructor = False
                    for fu in self.target_library["functions"]:
                        if fu["parent_hash"] == func["parent_hash"] and fu["func_type"] == FUNC_DEFAULT_CONSTRUCTOR:
                            found_default_constructor = True

                    # TODO: add code for other constructors!!!
                    if not found_default_constructor:
                        self.state.gen_this_function = False
                        os.unlink(f.name)
                        f.close()
                        return False
                    f.write("    //declare the RECORD first\n")
                    if anonymous:
                        f.write(
                            "    " + class_name.replace("::(anonymous namespace)", "") + " futag_target;\n")
                    else:
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
                    if anonymous:
                        f.write(
                            "    " + func["qname"].replace("::(anonymous namespace)", "") + "(")
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

        # ---------------------------------------------------------- #
        #  Parameter dispatch section                                  #
        # ---------------------------------------------------------- #

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
                    if curr_param["param_usage"] in ["FILE_DESCRIPTOR"]:
                        curr_name = "fd_" + curr_name + \
                            str(self.state.file_idx)  # string_prefix
                        self.state.file_idx += 1
                        curr_gen = self._gen_file_descriptor(
                            curr_name, gen_type_info)
                        self._append_gen_dict(curr_gen)
                        break
                    # GEN STRING SIZE

                    elif param_id > 0 and (func["params"][param_id - 1]["gen_list"][0]["gen_type"] in [GEN_CSTRING, GEN_WSTRING, GEN_CXXSTRING] or curr_param["param_usage"] == "SIZE_FIELD"):
                        if gen_type_info["type_name"] in ["size_t", "unsigned char", "char", "int", "unsigned", "unsigned int", "short", "unsigned short", "short int", "unsigned short int"]:
                            dyn_size_idx = 0
                            array_name = ""
                            if func["params"][param_id - 1]["gen_list"][0]["gen_type"] == GEN_CSTRING:
                                dyn_size_idx = self.state.dyn_cstring_size_idx
                                array_name = "dyn_cstring_size"
                            elif func["params"][param_id - 1]["gen_list"][0]["gen_type"] == GEN_WSTRING:
                                dyn_size_idx = self.state.dyn_wstring_size_idx
                                array_name = "dyn_wstring_size"
                            else:
                                dyn_size_idx = self.state.dyn_cxxstring_size_idx
                                array_name = "dyn_cxxstring_size"
                            curr_name = "sz_" + curr_name  # size_prefix
                            curr_gen = self._gen_strsize(
                                curr_name, curr_param["param_type"], dyn_size_idx, array_name)
                            self._append_gen_dict(curr_gen)
                            this_gen_size = True
                            break
                    if not this_gen_size:
                        curr_name = "b_" + curr_name  # builtin_prefix
                        curr_gen = self._gen_builtin(curr_name, gen_type_info)
                        self._append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_CFILE:
                    # GEN FILE NAME OR # GEN STRING
                    curr_name = "fc_" + curr_name  # string_prefix
                    self.state.file_idx += 1
                    curr_gen = self._gen_input_file(curr_name, gen_type_info)
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
                    if not anonymous:
                        print("!!!GEN_REFSTRING\n\n\n")
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
            self._gen_target_function(func, param_id, anonymous)

        else:
            if curr_param["gen_list"][0]["gen_type"] == GEN_STRUCT:
                # 1. Search for function call that generate struct type
                # 2. If not found, find in typdef the derived type of current struct and then take the action of 1.
                # 3. If not found, find the struct definition, check if the struct is simple and manual generate

                curr_name = "s_" + curr_name  # struct_prefix
                # A variable of structure type can be initialized with other functions.
                result_search_return_type = self._search_return_types(
                    curr_param["gen_list"], func, self.target_library['functions'])

                if not result_search_return_type:
                    # A struct type may be defined with different name through typdef
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
                        # Search typedef in return type of functions
                        result_search_typdef_return_type = self._search_return_types(
                            typedef_gen_list, func, self.target_library['functions'])
                        if result_search_typdef_return_type:
                            old_values = self._save_state()
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
                                self._gen_target_function(func, param_id, anonymous)
                                param_id -= 1
                                self._restore_state(old_values)
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
                    old_values = self._save_state()
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
                        self._gen_target_function(func, param_id, anonymous)
                        param_id -= 1
                        self._restore_state(old_values)

            if curr_param["gen_list"][0]["gen_type"] == GEN_CLASS:
                # 1. Search for function call that generate class type
                # 2. If not found, try to generate class through constructor/default constructor

                curr_name = "c_" + curr_name  # struct_prefix
                # A variable of structure type can be initialized with other functions.
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
                        old_values = self._save_state()
                        for curr_gen in curr_gen_list:
                            self._append_gen_dict(curr_gen)
                            #!!!call recursive
                            self.state.gen_lines += ["\n"]
                            self.state.param_list += [curr_name]
                            param_id += 1
                            self.state.var_function_idx += 1
                            self._gen_target_function(func, param_id, anonymous)
                            param_id -= 1
                            self._restore_state(old_values)
                    else:
                        gen_type_info = curr_param["gen_list"][0]
                        self.state.curr_func_log += f"- Could not generate for object: {str(gen_type_info)}. Could not find function call to generate this class!\n"
                        gen_curr_param = False
                else:
                    old_values = self._save_state()
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
                        self._gen_target_function(func, param_id, anonymous)
                        param_id -= 1
                        self._restore_state(old_values)

            if curr_param["gen_list"][0]["gen_type"] in [GEN_INCOMPLETE, GEN_VOID, GEN_FUNCTION, GEN_UNKNOWN]:
                gen_type_info = curr_param["gen_list"][0]
                self.state.curr_func_log += f"- Can not generate for object: {str(gen_type_info)}\n"
                gen_curr_param = False

            # if gen_type_info["gen_type"] == GEN_VOID:
            #     curr_name = "a_" + curr_name  # void_prefix
            #     self.state.curr_func_log += f"- Can not generate for object: {str(gen_type_info)}\n"
            #     gen_curr_param = False
            #     # curr_gen = self._gen_void(curr_name)
            #     # self._append_gen_dict(curr_gen)

            if not gen_curr_param:
                self.state.gen_this_function = False
            self.state.gen_lines += ["\n"]
            self.state.param_list += [curr_name]
            param_id += 1
            self._gen_target_function(func, param_id, anonymous)

    # ------------------------------------------------------------------ #
    #  gen_targets                                                        #
    # ------------------------------------------------------------------ #

    def gen_targets(self, anonymous: bool = False, from_list: str = "", max_wrappers: int = 10, max_functions: int = 10000):
        """
        Parameters
        ----------
        anonymous: bool
            option for generating fuzz-targets of non-public functions, default to False.
        """
        # Load the list of functions from the provided JSON file if specified
        if from_list:
            try:
                with open(from_list, 'r') as f:
                    function_list = json.load(f)
            except Exception as e:
                print(f"Error loading function list from {from_list}: {e}")
                function_list = []
        else:
            function_list = []

        self.gen_anonymous = anonymous
        self.max_wrappers = max_wrappers
        C_generated_function = []
        C_unknown_function = []
        Cplusplus_usual_class_method = []
        Cplusplus_static_class_method = []
        Cplusplus_anonymous_class_method = []

        func_index = 0

        for func in self.target_library["functions"]:
            if function_list and func["name"] not in function_list:
                continue
            func_index += 1
            if func_index > max_functions:
                break
            if func["access_type"] == AS_NONE and func["fuzz_it"] and func["storage_class"] < 2 and (func["parent_hash"] == ""):
                print(
                    "-- [Futag] Try to generate fuzz-driver for function: ", func["name"], "...")
                C_generated_function.append(func["name"])
                self.state.reset()
                self.state.curr_function = func
                if "(anonymous" in func["qname"]:
                    self._gen_target_function(func, 0, anonymous=True)
                else:
                    self._gen_target_function(func, 0, anonymous=False)

            # For C++, Declare object of class and then call the method
            if func["access_type"] == AS_PUBLIC and func["fuzz_it"] and func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR, FUNC_GLOBAL, FUNC_STATIC] and (not "::operator" in func["qname"]):
                Cplusplus_usual_class_method.append(func["qname"])
                print(
                    "-- [Futag] Try to generate fuzz-driver for class method: ", func["name"], "...")
                self.state.reset()
                self.state.curr_function = func
                if "(anonymous" in func["qname"]:
                    self._gen_target_function(func, 0, anonymous=True)
                else:
                    self._gen_target_function(func, 0, anonymous=False)

            # For C++, Call the static function of class without declaring object
            if func["access_type"] in [AS_NONE, AS_PUBLIC] and func["fuzz_it"] and func["func_type"] in [FUNC_CXXMETHOD, FUNC_GLOBAL, FUNC_STATIC] and func["storage_class"] == SC_STATIC:
                self.state.reset()
                self.state.curr_function = func
                if (not "(anonymous namespace)" in func["qname"]) and (not "::operator" in func["qname"]):
                    Cplusplus_static_class_method.append(func["qname"])
                if "(anonymous" in func["qname"]:
                    self._gen_target_function(func, 0, anonymous=True)

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
        json.dump(self.result_report, open(
            (self.build_path / "result-report.json").as_posix(), "w"))

    # ------------------------------------------------------------------ #
    #  Compilation methods                                                #
    # ------------------------------------------------------------------ #

    def compile_driver_worker(self, bgen_args):
        with open(bgen_args["error_path"], "w") as error_log_file:
            p = Popen(
                bgen_args["compiler_cmd"],
                stdout=PIPE,
                stderr=error_log_file,
                universal_newlines=True,
            )

        target_file = open(bgen_args["source_path"], "a")

        target_file.write("\n// Compile database: \n")
        target_file.write("/*\n")
        target_file.write(
            "command: " + bgen_args["compiler_info"]['command'] + "\n")
        target_file.write("location: " +
                          bgen_args["compiler_info"]['location'] + "\n")
        target_file.write("file: " + bgen_args["compiler_info"]['file'])
        target_file.write("\n*/\n")

        new_compiler_cmd = []
        compiler_cmd = bgen_args["compiler_cmd"]
        target_file.write("\n// Compile command:")
        target_file.write("\n/* \n")
        output, errors = p.communicate()
        if p.returncode:
            print(" ".join(bgen_args["compiler_cmd"]))
            print("\n-- [Futag] ERROR on target ",
                  bgen_args["target_name"], "\n")
            for c in compiler_cmd:
                if c.find(self.tmp_output_path.as_posix()) >= 0:
                    new_compiler_cmd.append(
                        c.replace(self.tmp_output_path.as_posix(), self.failed_path.as_posix()))
                else:
                    new_compiler_cmd.append(c)

        else:
            print("-- [Futag] Fuzz-driver ",
                  bgen_args["target_name"], " was compiled successfully!")
            for c in compiler_cmd:
                if c.find(self.tmp_output_path.as_posix()) >= 0:
                    new_compiler_cmd.append(
                        c.replace(self.tmp_output_path.as_posix(), self.succeeded_path.as_posix()))
                else:
                    new_compiler_cmd.append(c)

        target_file.write(" ".join(new_compiler_cmd))
        target_file.write("\n */\n")

        error_log_file = open(bgen_args["error_path"], "r")
        if error_log_file:
            target_file.write("\n// Error log:")
            target_file.write("\n/* \n")
            target_file.write("".join(error_log_file.readlines()))
            error_log_file.close()
            target_file.write("\n */\n")
        target_file.close()

    def compile_targets(self, workers: int = 4, keep_failed: bool = False, extra_params: str = "", extra_include: str = "", extra_dynamiclink: str = "", flags: str = "", coverage: bool = False, keep_original: bool = True):
        """_summary_

        Args:
            workers (int, optional): number of processes for compiling. Defaults to 4.
            keep_failed (bool, optional): option for saving not compiled fuzz-targets. Defaults to False.
            extra_params (str, optional): option for adding parameters while compiling. Defaults to "".
            extra_include (str, optional): option for adding included directories while compiling. Defaults to "".
            extra_dynamiclink (str, optional): option for adding dynamic libraries while compiling. Defaults to "".
            flags (str, optional): flags for compiling fuzz-drivers. Defaults to "-fsanitize=address -g -O0".
            coverage (bool, optional): option for adding coverage flag. Defaults to False.
            keep_original (bool, optional): option for keeping .futag-fuzz-drivers. Defaults to False.
        """

        # include_subdir = self.target_library["header_dirs"]
        # include_subdir = include_subdir + [x.parents[0].as_posix() for x in (self.build_path).glob("**/*.h")] + [x.parents[0].as_posix() for x in (self.build_path).glob("**/*.hpp")] + [self.build_path.as_posix()]

        # if (self.install_path / "include").exists():
        #     include_subdir = include_subdir + [x.parents[0].as_posix() for x in (self.install_path / "include").glob("**/*.h")] + [x.parents[0].as_posix() for x in (self.install_path / "include").glob("**/*.hpp")]
        # include_subdir = list(set(include_subdir))
        if not flags:
            if coverage:
                compiler_flags_aflplusplus = COMPILER_FLAGS + " " + \
                    COMPILER_COVERAGE_FLAGS + " " + DEBUG_FLAGS + " -fPIE"
                compiler_flags_libFuzzer = FUZZ_COMPILER_FLAGS + " " +\
                    COMPILER_COVERAGE_FLAGS + " " + DEBUG_FLAGS
            else:
                compiler_flags_aflplusplus = COMPILER_FLAGS + " " + DEBUG_FLAGS + " -fPIE "
                compiler_flags_libFuzzer = FUZZ_COMPILER_FLAGS + " " + DEBUG_FLAGS
        else:
            compiler_flags_aflplusplus = flags
            compiler_flags_libFuzzer = flags
            if coverage:
                compiler_flags_aflplusplus = COMPILER_COVERAGE_FLAGS + \
                    " " + compiler_flags_aflplusplus
                compiler_flags_libFuzzer = COMPILER_COVERAGE_FLAGS + " " + compiler_flags_libFuzzer

        generated_functions = [
            x for x in self.tmp_output_path.iterdir() if x.is_dir()]

        generated_targets = 0

        compile_cmd_list = []
        static_lib = []
        target_lib = [u for u in (self.library_root).glob(
            "**/*.a") if u.is_file()]
        if target_lib:
            static_lib = ["-Wl,--start-group"]
            for t in target_lib:
                static_lib.append(t.as_posix())
            static_lib.append("-Wl,--end-group")

        for func_dir in generated_functions:
            # Extract compiler cwd, to resolve relative includes
            search_curr_func = [
                f for f in self.target_library['functions'] if f['qname'].replace(":", "_") == func_dir.name]
            if not len(search_curr_func):
                search_curr_func = [
                    f for f in self.target_library['functions'] if 'anonymous_' + f['name'].replace(":", "_") == func_dir.name]
                if not len(search_curr_func):
                    continue
            current_func = search_curr_func[0]
            func_file_location = current_func["location"]["fullpath"]
            compiler_info = self._get_compile_command(func_file_location)

            # List of Pathlib (-I parameters) in compile command.
            # include_subdir = []
            include_paths = []
            if os.path.exists(compiler_info["location"]):
                current_location = os.getcwd()
                os.chdir(compiler_info["location"])
                for iter in compiler_info["command"].split(" "):
                    if iter[0:2] == "-I":
                        if pathlib.Path(iter[2:]).exists():
                            include_paths.append(pathlib.Path(iter[2:]).absolute().as_posix())
                os.chdir(current_location)

                if not "-fPIE" in compiler_flags_aflplusplus:
                    compiler_flags_aflplusplus += " -fPIE"

                if not "-ferror-limit=1" in compiler_flags_libFuzzer:
                    compiler_flags_libFuzzer += " -ferror-limit=1"

            compiler_path = ""
            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    compiler_path = self.futag_llvm_package / "bin/clang"
                else:
                    compiler_path = self.futag_llvm_package / "bin/clang++"
            else:
                if compiler_info["compiler"] == "CC":
                    compiler_path = self.futag_llvm_package / \
                        "AFLplusplus/usr/local/bin/afl-clang-fast"
                else:
                    compiler_path = self.futag_llvm_package / \
                        "AFLplusplus/usr/local/bin/afl-clang-fast++"

            current_func_compilation_opts = ""
            compilation_opts = ""

            for compiled_file in self.target_library["compiled_files"]:
                if func_file_location == compiled_file["filename"]:
                    compilation_opts = compiled_file["compiler_opts"]
                    for i in compiled_file["include_paths"]:
                        include_paths.append(i)

            current_func_compilation_opts = compilation_opts.split(' ')
            # Extract all include locations from compilation options
            compilation_opts_include_paths: List[pathlib.Path] = map(
                pathlib.Path,
                map(
                    current_func_compilation_opts.__getitem__,
                    [i + 1 for i,
                        x in enumerate(current_func_compilation_opts) if x == '-I']
                ))

            for include_path in compilation_opts_include_paths:
                include_paths.append(
                        pathlib.Path(include_path).absolute().as_posix())
            current_include = ["-I" + x for x in include_paths]
            current_include = list(set(current_include))
            fuzz_driver_dirs = [x for x in func_dir.iterdir() if x.is_dir()]
            for dir in fuzz_driver_dirs:
                # for target_src in [t for t in dir.glob("*") if t.is_file() and t.suffix in [".c", ".cc", ".cpp", ".log"]]:
                for target_src in [t for t in dir.glob("*") if t.is_file() and t.suffix in [".c", ".cc", ".cpp"]]:
                    target_path = dir.as_posix() + "/" + target_src.stem + ".out"
                    error_path = dir.as_posix() + "/" + target_src.stem + ".err"
                    generated_targets += 1
                    compiler = compiler_path.as_posix()
                    if self.alter_compiler:
                        compiler = self.alter_compiler

                    linking = []
                    if extra_dynamiclink:
                        linking = extra_dynamiclink.split(" ")
                    else:
                        linking = static_lib
                    if self.target_type == LIBFUZZER:
                        compiler_cmd = [compiler] + compiler_flags_libFuzzer.split(" ") + current_include + ["-I" + x for x in extra_include.split(
                            " ") if x.strip()] + extra_params.split(" ") + [target_src.as_posix()] + ["-o"] + [target_path] + linking
                    else:
                        compiler_cmd = [compiler] + compiler_flags_aflplusplus.split(" ") + current_include + ["-I" + x for x in extra_include.split(
                            " ") if x.strip()] + extra_params.split(" ") + [target_src.as_posix()] + ["-o"] + [target_path] + linking

                    compile_cmd_list.append({
                        "compiler_cmd": compiler_cmd,
                        "target_name": target_src.stem,
                        "error_path": error_path,
                        "source_path": target_src.as_posix(),
                        "binary_path": target_path,
                        "compiler_info": compiler_info,
                    })
        with Pool(workers) as p:
            p.map(self.compile_driver_worker, compile_cmd_list)

        # Extract the results of compilation

        compiled_targets_list = [
            x for x in self.tmp_output_path.glob("**/*.out") if x.is_file()]
        print("-- [Futag] collecting result ...")

        succeeded_tree = set()
        succeeded_dir = set()
        # for compiled_target in compiled_targets_list:
        #     if compiled_target.parents[0].as_posix() not in succeeded_tree:
        #         succeeded_tree.add(compiled_target.parents[0].as_posix())
        for compiled_target in compiled_targets_list:
            if compiled_target not in succeeded_tree:
                succeeded_tree.add(compiled_target)
                succeeded_dir.add(compiled_target.parents[0])
        for dir in succeeded_tree:
            if not (self.succeeded_path / dir.parents[1].name).exists():
                ((self.succeeded_path /
                 dir.parents[1].name)).mkdir(parents=True, exist_ok=True)
            # shutil.move(dir.parents[0].as_posix(), (self.succeeded_path / dir.parents[1].name).as_posix(), copy_function=shutil.copytree)
            copy_tree(dir.parents[0].as_posix(
            ), (self.succeeded_path / dir.parents[1].name / dir.parents[0].name).as_posix())

        if keep_failed:
            failed_tree = set()
            not_compiled_targets_list = [
                x for x in self.tmp_output_path.glob("**/*.cc") if x.is_file()]
            not_compiled_targets_list = not_compiled_targets_list + [
                x for x in self.tmp_output_path.glob("**/*.c") if x.is_file()]
            not_compiled_targets_list = not_compiled_targets_list + [
                x for x in self.tmp_output_path.glob("**/*.cpp") if x.is_file()]
            for target in not_compiled_targets_list:
                if target not in failed_tree:
                    failed_tree.add(target)
            for dir in failed_tree:
                if dir.parents[0] not in succeeded_dir:
                    if not (self.failed_path / dir.parents[1].name).exists():
                        ((self.failed_path /
                          dir.parents[1].name)).mkdir(parents=True, exist_ok=True)
                    # shutil.move(dir.parents[0].as_posix(), (self.failed_path / dir.parents[1].name).as_posix(), copy_function=shutil.copytree)
                    copy_tree(dir.parents[0].as_posix(
                    ), (self.failed_path / dir.parents[1].name / dir.parents[0].name).as_posix())
        else:
            delete_folder(self.failed_path)
        if not keep_original:
            delete_folder(self.tmp_output_path)

        print(
            "-- [Futag] Result of compiling: "
            + str(len(compiled_targets_list))
            + " fuzz-driver(s)\n"
        )

    # ------------------------------------------------------------------ #
    #  gen_targets_from_callstack                                         #
    # ------------------------------------------------------------------ #

    def gen_targets_from_callstack(self, target):
        found_function = None
        for func in self.target_library["functions"]:
            # if func["qname"] == target["qname"] and func["location"]["line"] == target["location"]["line"]and func["location"]["line"]["file"]== target["location"]["line"]:
            if func["qname"] == target["qname"]:
                found_function = func
                self._gen_target_function(func, 0)
        if not found_function:
            sys.exit("Function \"%s\" not found in library!" % target["qname"])
