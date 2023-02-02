"""
**************************************************
**      ______  __  __  ______  ___     ______  **
**     / ____/ / / / / /_  __/ /   |   / ____/  **
**    / /_    / / / /   / /   / /| |  / / __    **
**   / __/   / /_/ /   / /   / ___ | / /_/ /    **
**  /_/      \____/   /_/   /_/  |_| \____/     **
**                                              **
**     Fuzzing target Automated Generator       **
**             a tool of ISP RAS                **
**************************************************
** This module is for generating, compiling     **
** fuzz-drivers of functions in library         **
**************************************************
"""

import json
import pathlib
import copy
import os
from futag.sysmsg import *
from futag.preprocessor import *

from subprocess import Popen, PIPE
from multiprocessing import Pool
from typing import List
import shutil


class Generator:
    """Futag Generator"""

    def __init__(self, futag_llvm_package: str, library_root: str, target_type: int = LIBFUZZER, json_file: str = ANALYSIS_FILE_PATH, output_path=FUZZ_DRIVER_PATH, build_path=BUILD_PATH, install_path=INSTALL_PATH):
        """ Constructor of Generator class.

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

        self.gen_anonymous = False
        self.gen_this_function = True
        self.gen_lines = []
        self.buffer_size = []
        self.gen_free = []
        self.dyn_size_idx = 0
        self.file_idx = 0
        self.curr_function = None
        self.curr_func_log = ""
        self.curr_gen_string = -1
        self.param_list = []
        self.var_function_idx = 0

        # save the list of generated function for debugging
        self.target_extension = ""
        self.result_report = {}

        if (target_type > 1 or target_type < 0):
            raise ValueError(INVALID_TARGET_TYPE)

        self.target_type = target_type

        if pathlib.Path(self.futag_llvm_package).exists():
            self.futag_llvm_package = pathlib.Path(
                self.futag_llvm_package).absolute()
        else:
            raise ValueError(INVALID_FUTAG_PATH)

        if pathlib.Path(self.library_root).exists():
            self.library_root = pathlib.Path(self.library_root).absolute()
        else:
            raise ValueError(INVALID_LIBPATH)

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
            if (self.library_root / output_path).exists():
                delete_folder(self.library_root / output_path)
            if (self.library_root / tmp_output_path).exists():
                delete_folder(self.library_root / tmp_output_path)

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
            raise ValueError(INVALID_ANALYSIS_FILE)

        if not (self.library_root / build_path).exists():
            raise ValueError(INVALID_BUILPATH)
        self.build_path = self.library_root / build_path

        if not (self.library_root / install_path).exists():
            raise ValueError(INVALID_INSTALLPATH)
        self.install_path = self.library_root / install_path

    def __get_compile_command(self, file):
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
                    if command["command"].split(" ")[0] == "cc":
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
            return {
                "compiler": "CXX",
                "command": command["command"],
                "file": command["file"],
                "location": command["directory"]
            }
        else:
            return {
                "compiler": "CXX",
                "command": "",
                "file": "",
                "location": ""
            }

    def __gen_header(self, target_function_name):
        """ Generate header for the target function

        Args:
            target_function_name (string): the target function name.

        Returns:
            list: list of included header.
        """

        defaults = ["stdio.h", "stddef.h", "time.h",
                    "stdlib.h", "string.h", "stdint.h"]
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
        include_lines = []
        for i in defaults:
            include_lines.append("#include <" + i + ">\n")
        for i in included_headers:
            include_lines.append("#include " + i + "\n")
        return include_lines

    def __gen_builtin(self, param_name, gen_type_info):
        """Declare and assign value for a builtin type

        Args:
            param_name (str): parameter's name
            gen_type_info (dict): information of parameter's type

        Returns:
            dict: (gen_lines, gen_free, buffer_size)
        """
        return {
            "gen_lines": [
                "//GEN_BUILTIN\n",
                gen_type_info["type_name"] + " " + param_name + ";\n",
                "memcpy(&"+param_name+", pos, sizeof(" +
                gen_type_info["type_name"] + "));\n",
                "pos += sizeof(" + gen_type_info["type_name"] + ");\n"
            ],
            "gen_free": [],
            "buffer_size": ["sizeof(" + gen_type_info["type_name"]+")"]
        }

    def __gen_strsize(self, param_name, param_type, dyn_size_idx):
        return {
            "gen_lines": [
                "//GEN_SIZE\n",
                param_type + " " + param_name +
                " = (" + param_type +
                ") dyn_size[" + str(dyn_size_idx - 1) + "];\n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def __gen_cstring(self, param_name, gen_type_info, dyn_size_idx):
        """Declare and assign value for a C string type

        Args:
            param_name (str): parameter's name
            gen_type_info (dict): information of parameter's type
            dyn_size_idx (int): id of dynamic size

        Returns:
            dict: (gen_lines, gen_free, buffer_size)
        """
        ref_name = param_name
        if (gen_type_info["local_qualifier"]):
            ref_name = "r" + ref_name
        sizeof = ""

        malloc = gen_type_info["base_type_name"] + " " + ref_name + \
            " = (" + gen_type_info["base_type_name"] + \
            ") malloc(dyn_size[" + str(dyn_size_idx - 1) + "] + 1);\n"
        if "wchar_t" in gen_type_info["base_type_name"]:
            malloc = gen_type_info["base_type_name"] + " " + ref_name + \
                " = (" + gen_type_info["base_type_name"] + \
                ") malloc(sizeof(wchar_t)*dyn_size[" + \
                str(dyn_size_idx - 1) + "] + 1);\n"
        gen_lines = [
            "//GEN_CSTRING\n",
            malloc,
            "memset(" + ref_name +
            ", 0, dyn_size[" + str(dyn_size_idx - 1) + "] + 1);\n",
            "memcpy(" + ref_name +
            ", pos, dyn_size[" + str(dyn_size_idx - 1) + "] );\n",
            "pos += dyn_size[" + str(dyn_size_idx - 1) + "];\n",
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

    def __gen_cxxstring(self, param_name, gen_type_info, dyn_size_idx):
        """Declare and assign value for a C++ string type

        Args:
            param_name (str): parameter's name
            gen_type_info (dict): information of parameter's type for initializing

        Returns:
            dict: (gen_lines, gen_free, buffer_size)
        """
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
                gen_type_info["type_name"] + " " + param_name +
                "(pos, dyn_size[" + str(dyn_size_idx - 1) + "]); \n",
                "pos += dyn_size[" + str(dyn_size_idx - 1) + "];\n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def __gen_enum(self, enum_record, param_name, gen_type_info, compiler_info, anonymous: bool = False):

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
                    "_enum_index, pos, sizeof(unsigned int));\n",
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
                    "_enum_index, pos, sizeof(unsigned int));\n",
                    # "enum " + enum_name + " " + param_name + " = static_cast<enum " + enum_name +
                    enum_name + " " + param_name + " = static_cast<" + enum_name +
                    ">(" + param_name + "_enum_index % " + str(enum_length) + ");\n"
                ],
                "gen_free": [],
                "buffer_size": ["sizeof(unsigned int)"]
            }

    def __gen_array(self, param_name, gen_type_info):
        return {
            "gen_lines": [
                "//GEN_ARRAY\n",
                gen_type_info["type_name"] + " " + param_name + " = (" + gen_type_info["type_name"] + ") " +
                "malloc(sizeof(" + gen_type_info["base_type_name"] +
                ") * " + str(gen_type_info["length"]) + ");\n",
                "memcpy(" + param_name + ", pos, " + str(
                    gen_type_info["length"]) + " * sizeof(" + gen_type_info["base_type_name"] + "));\n",
                "pos += " +
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

    def __gen_void(self, param_name):
        return {
            "gen_lines": [
                "//GEN_VOID\n",
                "const char *" + param_name + "= NULL; \n",
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def __gen_qualifier(self, param_name, prev_param_name, gen_type_info):
        return {
            "gen_lines": [
                "//GEN_QUALIFIED\n",
                gen_type_info["type_name"] + " " +
                param_name + " = " + prev_param_name + ";\n"
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def __gen_pointer(self, param_name, prev_param_name, gen_type_info):
        return {
            "gen_lines": [
                "//GEN_POINTER\n",
                gen_type_info["type_name"] + " " + param_name +
                " = & " + prev_param_name + ";\n"
            ],
            "gen_free": [],
            "buffer_size": []
        }

    def __gen_struct(self, struct_name, struct, gen_info):
        gen_lines = [gen_info["type_name"] + " " + struct_name + ";\n"]
        gen_free = []
        buffer_size = []
        field_id = 0
        for field in struct["fields"]:
            curr_name = field["field_name"]
            for gen_type_info in field["gen_list"]:
                if gen_type_info["gen_type"] == GEN_BUILTIN:
                    if field_id > 0 and (struct["fields"][field_id - 1]["gen_list"][0]["gen_type"] in [GEN_CSTRING, GEN_CXXSTRING]):
                        if gen_type_info["type_name"] in ["size_t", "unsigned char", "char", "int", "unsigned", "unsigned int", "short", "unsigned short", "short int", "unsigned short int"]:
                            curr_name = "sz_" + curr_name  # size_prefix
                            curr_gen = self.__gen_strsize(
                                curr_name, gen_type_info["type_name"], self.dyn_size_idx)
                            buffer_size += curr_gen["buffer_size"]
                            gen_lines += curr_gen["gen_lines"]
                            gen_free += curr_gen["gen_free"]
                            this_gen_size = True  # with break, we may not need this variable :)
                            break

                    if not this_gen_size:
                        curr_name = "b_" + curr_name  # builtin_prefix
                        curr_gen = self.__gen_builtin(curr_name, gen_type_info)
                        buffer_size += curr_gen["buffer_size"]
                        gen_lines += curr_gen["gen_lines"]
                        gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_CSTRING:
                    curr_name = "strc_" + curr_name  # string_prefix
                    self.dyn_size_idx += 1
                    curr_gen = self.__gen_cstring(
                        curr_name, gen_type_info, self.dyn_size_idx)
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_CXXSTRING:
                    curr_name = "strcxx_" + curr_name  # string_prefix
                    self.dyn_size_idx += 1
                    curr_gen = self.__gen_cxxstring(
                        curr_name, gen_type_info, self.dyn_size_idx)
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
                        self.curr_func_log += f"- Can not generate for object: {str(gen_type_info)}\n"
                        self.gen_this_function = False
                    else:
                        compiler_info = self.__get_compile_command(self.curr_function["location"]["fullpath"])
                        curr_gen = self.__gen_enum(
                            found_enum, curr_name, gen_type_info, compiler_info, self.gen_anonymous)
                        buffer_size += curr_gen["buffer_size"]
                        gen_lines += curr_gen["gen_lines"]
                        gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_ARRAY:  # GEN_ARRAY
                    curr_name = "a_" + curr_name  # array_prefix
                    curr_gen = self.__gen_array(curr_name, gen_type_info)
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_QUALIFIER:
                    curr_name = "q_" + curr_name  # qualifier_prefix
                    curr_gen = self.__gen_qualifier(
                        curr_name, prev_param_name, gen_type_info)
                    buffer_size += curr_gen["buffer_size"]
                    gen_lines += curr_gen["gen_lines"]
                    gen_free += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_POINTER:
                    curr_name = "p_" + curr_name  # pointer_prefix
                    curr_gen = self.__gen_pointer(
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

    def __gen_union(self, param_name, class_record, gen_type_info):
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
                "memcpy(&"+param_name+", pos, sizeof(" +
                gen_type_info["type_name"] + "));\n",
                "pos += sizeof(" + gen_type_info["type_name"] + ");\n"
            ],
            "gen_free": [],
            "buffer_size": ["sizeof(" + gen_type_info["type_name"] + ")"]
        }

    def __gen_class(self, param_name, class_record):
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
                result.append(self.__gen_var_function(param_name, c))

        return result

    def __gen_input_file(self, param_name, gen_type_info):
        cur_gen_free = ["    " + x for x in self.gen_free]
        gen_lines = [
            "//GEN_INPUT_FILE\n",
            "const char* " + param_name + " = \"futag_input_file_" +
            str(self.file_idx - 1) + "\";\n",
            "FILE * fp_" + str(self.file_idx - 1) +
            " = fopen(" + param_name + ",\"w\");\n",
            "if (fp_" + str(self.file_idx - 1) + "  == NULL) {\n",
        ]
        gen_lines += cur_gen_free
        gen_lines += [
            "    return 0;\n",
            "}\n",
            "fwrite(pos, 1, file_size[" + str(self.file_idx - 1) +
            "], fp_" + str(self.file_idx - 1) + ");\n",
            "fclose(fp_" + str(self.file_idx - 1) + ");\n",
            "pos += file_size[" + str(self.file_idx - 1) + "];\n"
        ]
        return {
            "gen_lines": gen_lines,
            "gen_free": [],
            "buffer_size": []
        }

    def __search_in_typedefs(self, type_name, typedefs):
        # Are there multiple type definitions for the same data type???
        result = None
        for td in typedefs:
            if td["underlying_type"] == type_name:
                return td
        return result

    def __search_return_types(self, param_gen_list, curr_function, function_lists):
        result = []
        for f in function_lists:
            gen_list = []
            # To avoid infinite loop, we search only function with different name
            if f["qname"] == curr_function["qname"]:
                continue
            # Search only simple function with the same return type

            compiler_info = self.__get_compile_command(
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
                            curr_gen_field["gen_type"] = GEN_VARADDR
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

    def __append_gen_dict(self, curr_gen):
        if curr_gen:
            self.buffer_size += curr_gen["buffer_size"]
            self.gen_lines += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]

    def __gen_var_function(self, func_param_name: str, func):
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
            self.gen_this_function = False
            return gen_dict
        param_id = 0
        for arg in func["params"]:
            if len(arg["gen_list"]) > 1:
                curr_name = "_" + str(self.var_function_idx) + \
                    "_" + arg["param_name"]
            else:
                curr_name = curr_name = str(
                    self.var_function_idx) + "_" + arg["param_name"]
            prev_param_name = curr_name
            for gen_type_info in arg["gen_list"]:
                if gen_type_info["gen_type"] == GEN_BUILTIN:
                    this_gen_size = False
                    if param_id > 0 and (func["params"][param_id - 1]["gen_list"][0]["gen_type"] in [GEN_CSTRING, GEN_CXXSTRING] or arg["param_usage"] == "SIZE_FIELD"):
                        if gen_type_info["type_name"] in ["size_t", "unsigned char", "char", "int", "unsigned", "unsigned int", "short", "unsigned short", "short int", "unsigned short int"]:
                            curr_name = "sz_" + curr_name  # size_prefix
                            curr_gen = self.__gen_strsize(
                                curr_name, arg["param_type"], self.dyn_size_idx)
                            gen_dict["buffer_size"] += curr_gen["buffer_size"]
                            gen_dict["gen_lines"] += curr_gen["gen_lines"]
                            gen_dict["gen_free"] += curr_gen["gen_free"]
                            this_gen_size = True  # with break, we may not need this variable :)
                            break

                    if not this_gen_size:
                        curr_name = "b_" + curr_name  # builtin_prefix
                        curr_gen = self.__gen_builtin(curr_name, gen_type_info)
                        gen_dict["buffer_size"] += curr_gen["buffer_size"]
                        gen_dict["gen_lines"] += curr_gen["gen_lines"]
                        gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_CSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (arg["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or arg["param_name"] in ["filename", "file", "filepath"] or arg["param_name"].find('file') != -1 or arg["param_name"].find('File') != -1) and len(arg["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.file_idx += 1
                        curr_gen = self.__gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        curr_name = "str_" + curr_name  # string_prefix
                        self.dyn_size_idx += 1
                        curr_gen = self.__gen_cstring(
                            curr_name, gen_type_info, self.dyn_size_idx)
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_CXXSTRING:
                    curr_name = "str_" + curr_name  # string_prefix
                    self.dyn_size_idx += 1
                    curr_gen = self.__gen_cxxstring(
                        curr_name, gen_type_info, self.dyn_size_idx)
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
                        self.curr_func_log += f"- Can not generate for enum: {str(gen_type_info)}\n"
                        self.gen_this_function = False
                    else:
                        compiler_info = self.__get_compile_command(
                            func["location"]["fullpath"])
                        curr_gen = self.__gen_enum(
                            found_enum, curr_name, gen_type_info, compiler_info, self.gen_anonymous)
                        gen_dict["buffer_size"] += curr_gen["buffer_size"]
                        gen_dict["gen_lines"] += curr_gen["gen_lines"]
                        gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_ARRAY:  # GEN_ARRAY
                    curr_name = "a_" + curr_name  # array_prefix
                    curr_gen = self.__gen_array(curr_name, gen_type_info)
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_VOID:
                    curr_name = "a_" + curr_name  # void_prefix
                    self.curr_func_log += f"- Can not generate for object of void type: {str(gen_type_info)}\n"
                    self.gen_this_function = False

                if gen_type_info["gen_type"] == GEN_QUALIFIER:
                    curr_name = "q_" + curr_name  # qualifier_prefix
                    curr_gen = self.__gen_qualifier(
                        curr_name, prev_param_name, gen_type_info)
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]

                if gen_type_info["gen_type"] == GEN_POINTER:
                    curr_name = "p_" + curr_name  # qualifier_prefix
                    curr_gen = self.__gen_pointer(
                        curr_name, prev_param_name, gen_type_info)
                    gen_dict["buffer_size"] += curr_gen["buffer_size"]
                    gen_dict["gen_lines"] += curr_gen["gen_lines"]
                    gen_dict["gen_free"] += curr_gen["gen_free"]
                prev_param_name = curr_name

            param_id += 1
            param_list.append(curr_name)

        function_call = "//GEN_VAR_FUNCTION\n    " + func["return_type"] + " " + func_param_name + \
            " = " + func["qname"] + \
            "(" + ",".join(param_list)+");\n"

        gen_dict["gen_lines"] += [function_call]
        return gen_dict

    def __wrapper_file(self, func, anonymous: bool = False):

        # if anonymous:
        #     filename = func["name"]
        #     filepath = self.tmp_output_path / "anonymous"
        # else:
        filename = func["qname"]
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
            if file_index > 1000:
                break

        if file_index > 1000:
            return None
        (filepath / filename / dir_name).mkdir(parents=True, exist_ok=True)

        file_name = filename + \
            str(file_index) + "." + self.target_extension

        full_path = (filepath / filename / dir_name / file_name).as_posix()
        f = open(full_path, 'w')
        if f.closed:
            return None
        return f

    def __log_file(self, func, anonymous: bool = False):
        if anonymous:
            filename = func["name"]
            filepath = self.tmp_output_path / "anonymous"
        else:
            filename = func["qname"]
            filepath = self.tmp_output_path

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
            if file_index > 1000:
                break

        if file_index > 1000:
            return None
        (filepath / filename / dir_name).mkdir(parents=True, exist_ok=True)

        file_name = filename + str(file_index) + ".log"

        full_path = (filepath / filename / dir_name / file_name).as_posix()
        f = open(full_path, 'w')
        if f.closed:
            return None
        return f

    def __save_old_values(self):
        return {
            "buffer_size": copy.copy(self.buffer_size),
            "gen_lines": copy.copy(self.gen_lines),
            "gen_free": copy.copy(self.gen_free),
            "dyn_size_idx": copy.copy(self.dyn_size_idx),
            "var_function_idx": copy.copy(self.var_function_idx),
            "param_list": copy.copy(self.param_list),
            "curr_func_log": copy.copy(self.curr_func_log),
            "file_idx": copy.copy(self.file_idx),
            "gen_this_function": copy.copy(self.gen_this_function),
            "param_list": copy.copy(self.param_list)
        }

    def __retrieve_old_values(self, old_values):
        self.buffer_size = copy.copy(old_values["buffer_size"])
        self.gen_lines = copy.copy(old_values["gen_lines"])
        self.gen_free = copy.copy(old_values["gen_free"])
        self.dyn_size_idx = copy.copy(old_values["dyn_size_idx"])
        self.var_function_idx = copy.copy(old_values["var_function_idx"])
        self.param_list = copy.copy(old_values["param_list"])
        self.curr_func_log = copy.copy(old_values["curr_func_log"])
        self.file_idx = copy.copy(old_values["file_idx"])
        self.gen_this_function = copy.copy(old_values["gen_this_function"])
        self.param_list = copy.copy(old_values["param_list"])

    def __gen_target_function(self, func, param_id) -> bool:
        malloc_free = [
            "unsigned char *",
            "char *",
        ]

        if param_id == len(func['params']):
            if not self.gen_anonymous and "(anonymous namespace)" in func["qname"]:
                self.curr_func_log = f"This function is in anonymous namespace!"
                self.gen_this_function = False
            found_parent = None
            if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                # Find parent class
                for r in self.target_library["records"]:
                    if r["hash"] == func["parent_hash"]:
                        found_parent = r
                        break
                if not found_parent:
                    self.gen_this_function = False

            # If there is no buffer - return!
            if (not len(self.buffer_size) and not self.dyn_size_idx and not self.file_idx) or not self.gen_this_function:
                log = self.__log_file(func, self.gen_anonymous)
                if not log:
                    print(CANNOT_CREATE_LOG_FILE, func["qname"])
                else:
                    self.curr_func_log = f"Log for function: {func['qname']}\n{self.curr_func_log}"
                    log.write(self.curr_func_log)
                    log.close()
                return False
            # generate file name
            f = self.__wrapper_file(func, self.gen_anonymous)
            if not f:
                self.gen_this_function = False
                print(CANNOT_CREATE_WRAPPER_FILE, func["qname"])
                return False
            print(WRAPPER_FILE_CREATED, f.name)
            for line in self.__gen_header(func["location"]["fullpath"]):
                f.write(line)
            f.write('\n')
            compiler_info = self.__get_compile_command(
                func["location"]["fullpath"])

            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    f.write(LIBFUZZER_PREFIX_C)
                else:
                    f.write(LIBFUZZER_PREFIX_CXX)
            else:
                f.write(AFLPLUSPLUS_PREFIX)

            buffer_check = "    if (Fuzz_Size < " + \
                str(self.dyn_size_idx) + " + " + str(self.file_idx)
            f.write(buffer_check)
            if self.buffer_size:
                f.write(" + " + "+".join(self.buffer_size))
            f.write(") return 0;\n")

            if self.dyn_size_idx > 0:
                f.write("    size_t dyn_buffer = (size_t) ((Fuzz_Size - ( " + str(self.file_idx) + " + " +
                        str(self.dyn_size_idx))
                if self.buffer_size:
                    f.write(" + " + "+".join(self.buffer_size))
                f.write(")));\n")
                f.write("    //generate random array of dynamic string sizes\n")
                f.write("    size_t dyn_size[" +
                        str(self.dyn_size_idx) + "];\n")
                if self.dyn_size_idx > 1:
                    f.write("    srand(time(NULL));\n")
                    f.write("    if(dyn_buffer == 0) dyn_size[0] = dyn_buffer; \n")
                    f.write("    else dyn_size[0] = rand() % dyn_buffer; \n")
                    f.write("    size_t remain = dyn_size[0];\n")
                    f.write("    for(size_t i = 1; i< " +
                            str(self.dyn_size_idx) + " - 1; i++){\n")
                    f.write("        if(dyn_buffer - remain == 0) dyn_size[i] = dyn_buffer - remain;\n")
                    f.write("        else dyn_size[i] = rand() % (dyn_buffer - remain);\n")
                    f.write("        remain += dyn_size[i];\n")
                    f.write("    }\n")
                    f.write(
                        "    dyn_size[" + str(self.dyn_size_idx) + " - 1] = dyn_buffer - remain;\n")
                else:
                    f.write("    dyn_size[0] = dyn_buffer;\n")
                f.write(
                    "    //end of generation random array of dynamic string sizes\n")

            if self.file_idx > 0:
                if self.dyn_size_idx > 0:
                    f.write(
                        "    size_t file_buffer = (size_t) ((Fuzz_Size - dyn_buffer - (" + str(self.dyn_size_idx))
                else:
                    f.write(
                        "    size_t file_buffer = (size_t) ((Fuzz_Size - (" + str(self.dyn_size_idx))
                if self.buffer_size:
                    f.write(" + " + "+".join(self.buffer_size))
                f.write(")));\n")
                f.write("    //generate random array of dynamic file sizes\n")
                f.write("    size_t file_size[" +
                        str(self.file_idx) + "];\n")
                if self.file_idx > 1:
                    f.write("    srand(time(NULL));\n")
                    f.write("    if(file_buffer == 0) file_size[0] = file_buffer;\n")
                    f.write("    else file_size[0] = rand() % file_buffer;\n")
                    f.write("    size_t remain = file_size[0];\n")
                    f.write("    for(size_t i = 1; i< " +
                            str(self.file_idx) + " - 1; i++){\n")
                    f.write("        if(file_buffer - remain == 0) file_size[i] = file_buffer - remain;\n")
                    f.write("        else file_size[i] = rand() % (file_buffer - remain));\n")
                    f.write("        remain += file_size[i];\n")
                    f.write("    }\n")
                    f.write(
                        "    file_size[" + str(self.file_idx) + " - 1] = file_buffer - remain;\n")
                else:
                    f.write("    file_size[0] = file_buffer;\n")
                f.write(
                    "    //end of generation random array of dynamic file sizes\n")

            f.write("    uint8_t * pos = Fuzz_Data;\n")
            for line in self.gen_lines:
                f.write("    " + line)

            if func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                class_name = found_parent["qname"]
                if func["func_type"] in [FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                    f.write("    //declare the RECORD and call constructor\n")
                    f.write("    " + class_name + " futag_target" + "(")
                else:
                    # Find default constructor
                    # TODO: add code for other constructors
                    found_default_constructor = False
                    for fu in self.target_library["functions"]:
                        if fu["parent_hash"] == func["parent_hash"] and fu["func_type"] == FUNC_DEFAULT_CONSTRUCTOR:
                            found_default_constructor = True

                    # TODO: add code for other constructors!!!
                    if not found_default_constructor:
                        self.gen_this_function = False
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
            for arg in self.param_list:
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
            for line in self.gen_free:
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
            self.gen_this_function = False
            return False
        if curr_param["gen_list"][0]["gen_type"] in [GEN_BUILTIN, GEN_CSTRING, GEN_CXXSTRING, GEN_ENUM, GEN_ARRAY, GEN_INPUT_FILE, GEN_OUTPUT_FILE]:
            for gen_type_info in curr_param["gen_list"]:
                prev_param_name = curr_name
                if gen_type_info["gen_type"] == GEN_BUILTIN:
                    # GEN FILE DESCRIPTOR
                    # GEN STRING SIZE
                    this_gen_size = False
                    if param_id > 0 and (func["params"][param_id - 1]["gen_list"][0]["gen_type"] in [GEN_CSTRING, GEN_CXXSTRING] or curr_param["param_usage"] == "SIZE_FIELD"):
                        if gen_type_info["type_name"] in ["size_t", "unsigned char", "char", "int", "unsigned", "unsigned int", "short", "unsigned short", "short int", "unsigned short int"]:
                            curr_name = "sz_" + curr_name  # size_prefix
                            curr_gen = self.__gen_strsize(
                                curr_name, curr_param["param_type"], self.dyn_size_idx)
                            self.__append_gen_dict(curr_gen)
                            this_gen_size = True  # with break, we may not need this variable :)
                            break
                    if not this_gen_size:
                        curr_name = "b_" + curr_name  # builtin_prefix
                        curr_gen = self.__gen_builtin(curr_name, gen_type_info)
                        self.__append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_CSTRING:
                    # GEN FILE NAME OR # GEN STRING
                    if (curr_param["param_usage"] in ["FILE_PATH_READ", "FILE_PATH_WRITE", "FILE_PATH_RW", "FILE_PATH"] or curr_param["param_name"] in ["filename", "file", "filepath"] or curr_param["param_name"].find('file') != -1 or curr_param["param_name"].find('File') != -1) and len(curr_param["gen_list"]) == 1:
                        curr_name = "f_" + curr_name  # string_prefix
                        self.file_idx += 1
                        curr_gen = self.__gen_input_file(
                            curr_name, gen_type_info)
                    else:
                        # GEN STRING
                        curr_name = "str_" + curr_name  # string_prefix
                        self.dyn_size_idx += 1
                        curr_gen = self.__gen_cstring(
                            curr_name, gen_type_info, self.dyn_size_idx)

                    self.__append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_CXXSTRING:
                    curr_name = "str_" + curr_name  # string_prefix
                    self.dyn_size_idx += 1
                    curr_gen = self.__gen_cxxstring(
                        curr_name, gen_type_info, self.dyn_size_idx)
                    self.__append_gen_dict(curr_gen)

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
                        self.curr_func_log += f"- Can not generate for enum: {str(gen_type_info)}\n"
                        gen_curr_param = False
                    else:
                        compiler_info = self.__get_compile_command(
                            func["location"]["fullpath"])
                        curr_gen = self.__gen_enum(
                            found_enum, curr_name, gen_type_info, compiler_info, self.gen_anonymous)
                        self.__append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_UNION:
                    curr_name = "u_" + curr_name  # union_prefix
                    curr_gen = self.__gen_union(curr_name, gen_type_info)
                    self.__append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_ARRAY:  # GEN_ARRAY
                    curr_name = "a_" + curr_name  # array_prefix
                    curr_gen = self.__gen_array(curr_name, gen_type_info)
                    self.__append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_QUALIFIER:
                    curr_name = "q_" + curr_name  # qualifier_prefix
                    curr_gen = self.__gen_qualifier(
                        curr_name, prev_param_name, gen_type_info)
                    self.__append_gen_dict(curr_gen)

                if gen_type_info["gen_type"] == GEN_POINTER:
                    curr_name = "p_" + curr_name  # qualifier_prefix
                    curr_gen = self.__gen_pointer(
                        curr_name, prev_param_name, gen_type_info)
                    self.__append_gen_dict(curr_gen)
                prev_param_name = curr_name
            if not gen_curr_param:
                self.gen_this_function = False
            self.gen_lines += ["\n"]
            self.param_list += [curr_name]
            param_id += 1
            self.__gen_target_function(func, param_id)

        else:
            if curr_param["gen_list"][0]["gen_type"] == GEN_STRUCT:
                # 1. Search for function call that generate struct type
                # 2. If not found, find in typdef the derived type of current struct and then take the action of 1.
                # 3. If not found, find the struct definition, check if the struct is simple and manual generate

                curr_name = "s_" + curr_name  # struct_prefix
                # A variable of structure type can be initialized with other functions.
                result_search_return_type = self.__search_return_types(
                    curr_param["gen_list"], func, self.target_library['functions'])

                if not result_search_return_type:
                    # A struct type may be defined with different name through typdef
                    result_search_typedefs = self.__search_in_typedefs(
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
                        result_search_typdef_return_type = self.__search_return_types(
                            typedef_gen_list, func, self.target_library['functions'])
                        if result_search_typdef_return_type:
                            old_values = self.__save_old_values()
                            for curr_return_func in result_search_typdef_return_type:
                                self.var_function_idx += 1
                                self.gen_lines += ["\n"]
                                self.param_list += [curr_name]
                                curr_gen = self.__gen_var_function(
                                    curr_name, curr_return_func["function"])
                                self.__append_gen_dict(curr_gen)
                                #!!!call recursive
                                param_id += 1
                                self.__gen_target_function(func, param_id)
                                param_id -= 1
                                self.__retrieve_old_values(old_values)
                        else:
                            found_struct = None
                            for record in self.target_library["records"]:
                                if record["type"] == STRUCT_RECORD and record["name"] == curr_param["gen_list"][0]["type_name"].split(" ")[1] and record["is_simple"]:
                                    found_struct = record
                                    break
                            if found_struct:
                                curr_gen = self.__gen_struct(
                                    curr_name, record, gen_type_info)
                                self.__append_gen_dict(curr_gen)
                            else:
                                _tmp = curr_param["gen_list"][0]
                                self.curr_func_log += f"- Could not generate for object: {str(_tmp)}. Could not find function call to generate this struct!\n"
                        gen_curr_param = False
                    else:
                        _tmp = curr_param["gen_list"][0]
                        self.curr_func_log += f"- Could not generate for object: {str(_tmp)}. Could not create function call to generate this struct, and the definition of struct not found!\n"
                        gen_curr_param = False
                else:
                    old_values = self.__save_old_values()
                    for curr_return_func in result_search_return_type:
                        self.var_function_idx += 1
                        self.gen_lines += ["\n"]
                        self.param_list += [curr_name]
                        curr_gen = self.__gen_var_function(
                            curr_name, curr_return_func["function"])
                        self.__append_gen_dict(curr_gen)
                        #!!!call recursive
                        param_id += 1
                        self.__gen_target_function(func, param_id)
                        param_id -= 1
                        self.__retrieve_old_values(old_values)

            if curr_param["gen_list"][0]["gen_type"] == GEN_CLASS:
                # 1. Search for function call that generate class type
                # 2. If not found, try to generate class through constructor/default constructor

                curr_name = "c_" + curr_name  # struct_prefix
                # A variable of structure type can be initialized with other functions.
                result_search_return_type = self.__search_return_types(
                    curr_param["gen_list"], func, self.target_library['functions'])

                if not result_search_return_type:
                    found_class = None
                    for record in self.target_library["records"]:
                        if record["type"] == CLASS_RECORD and record["name"] == curr_param["gen_list"][0]["type_name"]:
                            found_class = record
                            break
                    if found_class:
                        curr_gen_list = self.__gen_class(
                            curr_name, found_class)
                        old_values = self.__save_old_values()
                        for curr_gen in curr_gen_list:
                            self.__append_gen_dict(curr_gen)
                            #!!!call recursive
                            self.gen_lines += ["\n"]
                            self.param_list += [curr_name]
                            param_id += 1
                            self.var_function_idx += 1
                            self.__gen_target_function(func, param_id)
                            param_id -= 1
                            self.__retrieve_old_values(old_values)
                    else:
                        gen_type_info = curr_param["gen_list"][0]
                        self.curr_func_log += f"- Could not generate for object: {str(gen_type_info)}. Could not find function call to generate this class!\n"
                        gen_curr_param = False
                else:
                    old_values = self.__save_old_values()
                    for curr_return_func in result_search_return_type:
                        self.var_function_idx += 1
                        self.gen_lines += ["\n"]
                        self.param_list += [curr_name]
                        curr_gen = self.__gen_var_function(
                            curr_name, curr_return_func["function"])
                        self.__append_gen_dict(curr_gen)
                        #!!!call recursive
                        param_id += 1
                        self.__gen_target_function(func, param_id)
                        param_id -= 1
                        self.__retrieve_old_values(old_values)

            if curr_param["gen_list"][0]["gen_type"] in [GEN_INCOMPLETE, GEN_VOID, GEN_FUNCTION, GEN_UNKNOWN]:
                gen_type_info = curr_param["gen_list"][0]
                self.curr_func_log += f"- Can not generate for object: {str(gen_type_info)}\n"
                gen_curr_param = False

            # if gen_type_info["gen_type"] == GEN_VOID:
            #     curr_name = "a_" + curr_name  # void_prefix
            #     self.curr_func_log += f"- Can not generate for object: {str(gen_type_info)}\n"
            #     gen_curr_param = False
            #     # curr_gen = self.__gen_void(curr_name)
            #     # self.__append_gen_dict(curr_gen)

            if not gen_curr_param:
                self.gen_this_function = False
            self.gen_lines += ["\n"]
            self.param_list += [curr_name]
            param_id += 1
            self.__gen_target_function(func, param_id)

    def gen_targets(self, anonymous: bool = False):
        """
        Parameters
        ----------
        anonymous: bool
            option for generating fuzz-targets of non-public functions, default to False.
        """
        self.gen_anonymous = anonymous
        C_generated_function = []
        C_unknown_function = []
        Cplusplus_usual_class_method = []
        Cplusplus_static_class_method = []
        Cplusplus_anonymous_class_method = []
        for func in self.target_library["functions"]:
            # For C
            if func["access_type"] == AS_NONE and func["fuzz_it"] and func["storage_class"] < 2 and (func["parent_hash"] == ""):
                print(
                    "-- [Futag] Try to generate fuzz-driver for function: ", func["name"], "...")
                C_generated_function.append(func["name"])
                self.gen_this_function = True
                self.buffer_size = []
                self.gen_lines = []
                self.gen_free = []
                self.dyn_size_idx = 0
                self.file_idx = 0
                self.var_function_idx = 0
                self.param_list = []
                self.curr_function = func
                self.curr_func_log = ""
                self.__gen_target_function(func, 0)

            # For C++, Declare object of class and then call the method
            if func["access_type"] == AS_PUBLIC and func["fuzz_it"] and func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR, FUNC_GLOBAL, FUNC_STATIC] and (not "::operator" in func["qname"]):
                Cplusplus_usual_class_method.append(func["qname"])
                print(
                    "-- [Futag] Try to generate fuzz-driver for class method: ", func["name"], "...")
                self.gen_this_function = True
                self.buffer_size = []
                self.gen_lines = []
                self.gen_free = []
                self.dyn_size_idx = 0
                self.file_idx = 0
                self.var_function_idx = 0
                self.param_list = []
                self.curr_function = func
                self.curr_func_log = ""
                self.__gen_target_function(func, 0)

            # For C++, Call the static function of class without declaring object
            if func["access_type"] in [AS_NONE, AS_PUBLIC] and func["fuzz_it"] and func["func_type"] in [FUNC_CXXMETHOD, FUNC_GLOBAL, FUNC_STATIC] and func["storage_class"] == SC_STATIC:
                if (not "(anonymous namespace)" in func["qname"]) and (not "::operator" in func["qname"]):
                    Cplusplus_static_class_method.append(func["qname"])

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
            print("\n-- [Futag] ERROR on target ", bgen_args["target_name"], "\n")
            for c in compiler_cmd:
                if c.find(self.tmp_output_path.as_posix()) >= 0:
                    new_compiler_cmd.append(c.replace(self.tmp_output_path.as_posix(), self.failed_path.as_posix()))
                else:
                    new_compiler_cmd.append(c)

        else:
            print("-- [Futag] Fuzz-driver ", bgen_args["target_name"], " was compiled successfully!")
            for c in compiler_cmd:
                if c.find(self.tmp_output_path.as_posix()) >= 0:
                    new_compiler_cmd.append(c.replace(self.tmp_output_path.as_posix(), self.succeeded_path.as_posix()))
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
        

    def compile_targets(self, workers: int = 4, keep_failed: bool = False, extra_include: str = "", extra_dynamiclink: str = "", flags: str = "", coverage: bool=False):
        """
        Parameters
        ----------
        workers: int
            number of processes for compiling, default to 4.
        keep_failed: bool
            option for saving not compiled fuzz-targets, default to False.
        extra_include: str
            option for add included directories while compiling, default to empty string.
        extra_dynamiclink: str
            option for add dynamic libraries while compiling, default to empty string.
        flags: str
            flags for compiling fuzz-drivers, default to "-fsanitize=address,fuzzer -g -O0".
        """

        # include_subdir = self.target_library["header_dirs"]
        # include_subdir = include_subdir + [x.parents[0].as_posix() for x in (self.build_path).glob("**/*.h")] + [x.parents[0].as_posix() for x in (self.build_path).glob("**/*.hpp")] + [self.build_path.as_posix()]

        # if (self.install_path / "include").exists():
        #     include_subdir = include_subdir + [x.parents[0].as_posix() for x in (self.install_path / "include").glob("**/*.h")] + [x.parents[0].as_posix() for x in (self.install_path / "include").glob("**/*.hpp")]
        # include_subdir = list(set(include_subdir))
        if not flags:
            if coverage:
                compiler_flags_aflplusplus = COMPILER_COVERAGE_FLAGS + " " + DEBUG_FLAGS + " -fPIE"
                compiler_flags_libFuzzer = FUZZ_COMPILER_FLAGS + " " +\
                    COMPILER_COVERAGE_FLAGS + " " + DEBUG_FLAGS
            else:
                compiler_flags_aflplusplus = DEBUG_FLAGS + " -fPIE "
                compiler_flags_libFuzzer = FUZZ_COMPILER_FLAGS + " " + DEBUG_FLAGS
        else:
            compiler_flags_aflplusplus = flags
            compiler_flags_libFuzzer = flags
            if coverage:
                compiler_flags_aflplusplus = COMPILER_COVERAGE_FLAGS + " " + compiler_flags_aflplusplus
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
                f for f in self.target_library['functions'] if f['qname'] == func_dir.name]
            if not len(search_curr_func):
                continue
            current_func = search_curr_func[0]
            func_file_location = current_func["location"]["fullpath"]
            compiler_info = self.__get_compile_command(func_file_location)
            include_subdir = []

            if not os.path.exists(compiler_info["location"]):
                continue
            current_location = os.getcwd()
            os.chdir(compiler_info["location"])
            for iter in compiler_info["command"].split(" "):
                if iter[0:2] == "-I":
                    if pathlib.Path(iter[2:]).exists():
                        include_subdir.append(
                            "-I" + pathlib.Path(iter[2:]).absolute().as_posix() + "/")
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
                    compiler_path = self.futag_llvm_package / "AFLplusplus/usr/local/bin/afl-clang-fast"
                else:
                    compiler_path = self.futag_llvm_package / "AFLplusplus/usr/local/bin/afl-clang-fast++"

            current_func_compilation_opts = ""
            compilation_opts = ""

            for compiled_file in self.target_library["compiled_files"]:
                if func_file_location == compiled_file["filename"]:
                    compilation_opts = compiled_file["compiler_opts"]
            current_func_compilation_opts = compilation_opts.split(' ')
            # Extract all include locations from compilation options
            include_paths: List[pathlib.Path] = map(
                pathlib.Path,
                map(
                    current_func_compilation_opts.__getitem__,
                    [i + 1 for i,
                        x in enumerate(current_func_compilation_opts) if x == '-I']
                ))

            resolved_include_paths: List[pathlib.Path] = []
            for include_path in include_paths:
                if include_path.is_absolute():
                    resolved_include_paths.append(include_path)
                else:
                    # Resolve relative include paths (e.g. in this case: -I.. -I.)
                    resolved_include_paths.append(
                        pathlib.Path(include_path).absolute())

            current_include = []
            if not include_subdir:
                for i in resolved_include_paths:
                    current_include.append("-I" + i + "/")
            else:
                for i in include_subdir:
                    current_include.append(i)

            fuzz_driver_dirs = [x for x in func_dir.iterdir() if x.is_dir()]
            for dir in fuzz_driver_dirs:
                # for target_src in [t for t in dir.glob("*"+self.target_extension) if t.is_file()]:
                for target_src in [t for t in dir.glob("*") if t.is_file() and t.suffix in [".c", ".cc", ".cpp"]]:
                    target_path = dir.as_posix() + "/" + target_src.stem + ".out"
                    error_path = dir.as_posix() + "/" + target_src.stem + ".err"
                    generated_targets += 1
                    if self.target_type == LIBFUZZER:
                        compiler_cmd = [compiler_path.as_posix()] + compiler_flags_libFuzzer.split(" ") + current_include + [extra_include] + [target_src.as_posix()] + ["-o"] + [target_path] + static_lib + extra_dynamiclink.split(" ")
                    else:
                        compiler_cmd = [compiler_path.as_posix()] + compiler_flags_aflplusplus.split(" ") + current_include + [extra_include] +[target_src.as_posix()] + ["-o"] + [target_path] + static_lib + extra_dynamiclink.split(" ")

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
        # for compiled_target in compiled_targets_list:
        #     if compiled_target.parents[0].as_posix() not in succeeded_tree:
        #         succeeded_tree.add(compiled_target.parents[0].as_posix())
        for compiled_target in compiled_targets_list:
            if compiled_target not in succeeded_tree:
                succeeded_tree.add(compiled_target)
        for dir in succeeded_tree:
            if not (self.succeeded_path / dir.parents[1].name).exists():
                ((self.succeeded_path / dir.parents[1].name)).mkdir(parents=True, exist_ok=True)
            shutil.move(dir.parents[0].as_posix(), (self.succeeded_path / dir.parents[1].name).as_posix(), copy_function=shutil.copytree)

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
                if not (self.failed_path / dir.parents[1].name).exists():
                    ((self.failed_path / dir.parents[1].name)).mkdir(parents=True, exist_ok=True)
                shutil.move(dir.parents[0].as_posix(), (self.failed_path / dir.parents[1].name).as_posix(), copy_function=shutil.copytree)
        else:
            delete_folder(self.failed_path)
        delete_folder(self.tmp_output_path)

        print(
            "-- [Futag] Result of compiling: "
            + str(len(compiled_targets_list))
            + " fuzz-driver(s)\n"
        )

    def gen_targets_from_callstack(self, target):
        found_function = None
        for func in self.target_library["functions"]:
            # if func["qname"] == target["qname"] and func["location"]["line"] == target["location"]["line"]and func["location"]["line"]["file"]== target["location"]["line"]:
            if func["qname"] == target["qname"]:
                found_function = func
                self.__gen_target_function(func, 0)
        if not found_function:
            raise ValueError("Function \"%s\" not found in library!" % target["qname"])