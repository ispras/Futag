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
import string
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

        self.gen_func_params = []
        self.gen_free = []
        self.gen_this_function = True
        self.buf_size_arr = []
        self.dyn_size = 0
        self.curr_gen_string = -1
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
            self.tmp_output_path = (self.library_root / tmp_output_path).absolute()
            
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
        self.var_function = 0
        self.var_files = 0

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

        defaults = ["stdio.h", "stddef.h", "stdlib.h", "string.h", "stdint.h"]
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

    def __gen_builtin(self, type_name, var_name):

        return {
            "gen_lines": [
                "//GEN_BUILTIN\n",
                type_name + " " + var_name + ";\n",
                "memcpy(&"+var_name+", pos, sizeof(" + type_name + "));\n",
                "pos += sizeof(" + type_name + ");\n"
            ],
            "gen_free": []
        }

    def __gen_size(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_SIZE\n",
                type_name + " " + var_name +
                " = (" + type_name + ") dyn_size;\n",
            ],
            "gen_free": []
        }

    def __gen_string(self, type_name, var_name, parent_type):
        if (len(parent_type) > 0):
            return {
                "gen_lines": [
                    "//GEN_STRING\n",
                    parent_type + " r" + var_name + " = (" + parent_type + ") " +
                    "malloc(sizeof(char) * dyn_size + 1);\n",
                    "memset(r" + var_name+", 0, sizeof(char) * dyn_size + 1);\n",
                    "memcpy(r" + var_name+", pos, sizeof(char) * dyn_size );\n",
                    "pos += sizeof(char) * dyn_size ;\n",
                    type_name + " " + var_name + "= r" + var_name + ";\n"
                ],
                "gen_free": [
                    # "if (dyn_size > 0 && strlen(r" + var_name + \
                    # ") > 0) {\n",
                    "if (r" + var_name + ") {\n",
                    "    free(r" + var_name + ");\n",
                    "    r" + var_name + " = NULL;\n",
                    "}\n"
                ]
            }
        return {
            "gen_lines": [
                "//GEN_STRING\n",
                type_name + " " + var_name + " = (" + type_name + ") " +
                "malloc(sizeof(char) * dyn_size + 1);\n",
                "memset(" + var_name+", 0, sizeof(char) * dyn_size + 1);\n",
                "memcpy(" + var_name+", pos, sizeof(char) * dyn_size );\n",
                "pos += sizeof(char) * dyn_size ;\n"
            ],
            "gen_free": [
                # "if (dyn_size > 0 && strlen(" + var_name + \
                # ") > 0) {\n",
                "if (" + var_name + ") {\n",
                "    free( " + var_name + ");\n",
                "    " + var_name + " = NULL;\n",
                "}\n"
            ]
        }

    def __gen_enum(self, enum_record, var_name, compiler_info):
        enum_length = len(enum_record["enum_values"])
        if compiler_info["compiler"] == "CC":
            return {
                "gen_lines": [
                    "//GEN_ENUM\n",
                    "unsigned int " + var_name + "_enum_index; \n",
                    "memcpy(&" + var_name +
                    "_enum_index, pos, sizeof(unsigned int));\n",
                    "enum " + enum_record["qname"] + " " + var_name + " = " +
                    var_name + "_enum_index % " + str(enum_length) + ";\n"
                ],
            }
        else:
            return {
                "gen_lines": [
                    "//GEN_ENUM\n",
                    "unsigned int " + var_name + "_enum_index; \n",
                    "memcpy(&" + var_name +
                    "_enum_index, pos, sizeof(unsigned int));\n",
                    "enum " + enum_record["qname"] + " " + var_name + " = static_cast<enum " + enum_record["qname"] +
                    ">(" + var_name + "_enum_index % " + str(enum_length) + ");\n"
                ],
            }

    def __gen_anonymous_enum(self, enum_record, var_name, compiler_info):
        enum_length = len(enum_record["enum_values"])
        if compiler_info["compiler"] == "CC":
            return {
                "gen_lines": [
                    "//GEN_ENUM\n",
                    "unsigned int " + var_name + "_enum_index; \n",
                    "memcpy(&" + var_name +
                    "_enum_index, pos, sizeof(unsigned int));\n",
                    "enum " + enum_record["name"] + " " + var_name + " = " +
                    var_name + "_enum_index % " + str(enum_length) + ";\n"
                ],
            }
        else:
            return {
                "gen_lines": [
                    "//GEN_ENUM\n",
                    "unsigned int " + var_name + "_enum_index; \n",
                    "memcpy(&" + var_name +
                    "_enum_index, pos, sizeof(unsigned int));\n",
                    "enum " + enum_record["name"] + " " + var_name + " = static_cast<enum " + enum_record["name"] +
                    ">(" + var_name + "_enum_index % " + str(enum_length) + ");\n"
                ],
            }

    def __gen_array(self, var_name):
        return {
            "gen_lines": [
                "//GEN_ARRAY\n",
                
            ],
            "gen_free": []
        }

    def __gen_void(self, var_name):
        return {
            "gen_lines": [
                "//GEN_VOID\n",
                "const char *" + var_name + "= NULL; \n",
            ],
            "gen_free": []
        }

    def __gen_qualifier(self, type_name, var_name, parent_type, parent_gen, param_id):

        if parent_type in ["const char *", "const unsigned char *"]:
            self.dyn_size += 1
            temp_type = parent_type[6:]
            self.curr_gen_string = param_id
            return {
                "gen_lines": [
                    "//GEN_STRING\n",
                    temp_type + " s" + var_name + " = (" + temp_type + ") " +
                    "malloc(sizeof(char) * dyn_size + 1);\n",
                    "memset(s" + var_name+", 0, sizeof(char) * dyn_size + 1);\n",
                    "memcpy(s" + var_name+", pos, sizeof(char) * dyn_size );\n",
                    "pos += sizeof(char) * dyn_size ;\n",
                    parent_type + " u" + var_name + "= s" + var_name + ";\n",
                    "//GEN_QUALIFIED\n",
                    type_name + " " + var_name + " = u" + var_name + ";\n",
                ],
                "gen_free": [
                    "if (s" + var_name + ") {\n",
                    "    free(s" + var_name + ");\n",
                    "    s" + var_name + " = NULL;\n",
                    "}\n"
                ],
                "buf_size": "sizeof(char)",
            }
        if parent_type in ["char *", "unsigned char *"]:
            self.dyn_size += 1
            self.curr_gen_string = param_id
            return {
                "gen_lines": [
                    "//GEN_STRING\n",
                    parent_type + " s" + var_name + " = (" + parent_type + ") " +
                    "malloc(sizeof(char) * dyn_size + 1);\n",
                    "memset(s" + var_name+", 0, sizeof(char) * dyn_size + 1);\n",
                    "memcpy(s" + var_name+", pos, sizeof(char) * dyn_size );\n",
                    "pos += sizeof(char) * dyn_size ;\n",
                    "//GEN_QUALIFIED\n",
                    type_name + " " + var_name + " = s" + var_name + ";\n"
                ],
                "gen_free": [
                    "if (s" + var_name + " ) {\n",
                    "    free(s" + var_name + ");\n",
                    "    s" + var_name + " = NULL;\n",
                    "}\n"
                ],
                "buf_size": "sizeof(char)"
            }
        if parent_gen == "incomplete":
            self.gen_this_function = False
            return {
                "gen_lines": [
                    "//GEN_VOID\n"
                ],
                "gen_free": [],
                "buf_size": ""
            }
        return {
            "gen_lines": [
                "//GEN_QUALIFIED\n",
                parent_type + " u" + var_name + ";\n",
                "memcpy(&u"+var_name+", pos, sizeof(" + parent_type + "));\n",
                "pos += sizeof(" + parent_type + ");\n",
                type_name + " " + var_name + " = u" + var_name + ";\n"
            ],
            "gen_free": [],
            "buf_size": ""
        }

    def __gen_pointer(self, type_name, var_name, parent_type):
        return {
            "gen_lines": [
                "//GEN_POINTER\n",
                parent_type + " r" + var_name + ";\n",
                "memcpy(&r" + var_name + ", pos, sizeof(" + parent_type + "));\n",
                "pos += sizeof(" + parent_type + ");\n",
                type_name + " " + var_name + "= &r" + var_name + ";\n"
            ],
            "gen_free": []
        }

    def __gen_struct(self, type_name, var_name):
        return False
        # return {
        #     "gen_lines": [
        #         "//GEN_STRUCT\n"
        #     ],
        #     "gen_free": []
        # }

    def __gen_input_file(self, var_name):
        cur_gen_free = ["    " + x for x in self.gen_free]
        gen_lines = [
            "//GEN_INPUT_FILE\n",
            "const char* " + var_name + " = \"futag_input_file\";\n",
            "FILE *fp"+str(self.var_files) +
            " = fopen(" + var_name + ",\"w\");\n",
            "if (fp"+str(self.var_files)+"  == NULL) {\n",
        ] + cur_gen_free + ["    return 0;\n",
                            "}\n",
                            "fwrite(pos, 1, dyn_size, fp" +
                            str(self.var_files)+");\n",
                            "fclose(fp"+str(self.var_files)+");\n",
                            "pos += dyn_size;\n"
                            ]
        return {
            "gen_lines": gen_lines,
            "gen_free": []
        }

    def __gen_var_function(self, parent_func, func, var_name):
        """ Initialize for argument of function call """
        curr_gen_func_params = []
        curr_gen_free = []
        curr_buf_size_arr = []
        curr_dyn_size = 0
        param_list = []
        param_id = 0
        curr_gen_string = -1
        for arg in func["params"]:
            param_list.append("f"+str(self.var_function) +
                              "_" + arg["param_name"])
            if arg["generator_type"] == GEN_BUILTIN:
                if arg["param_type"].split(" ")[0] in ["volatile", "const"]:
                    if arg["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                        if curr_gen_string >= 0:
                            var_curr_gen = {
                                "gen_lines": [
                                    "//GEN_SIZE\n",
                                    arg["param_type"].split(" ")[1] + " uf"+str(
                                        self.var_function)+"_" + arg["param_name"] + " = (" + arg["param_type"].split(" ")[1] + ") dyn_size;\n",
                                    arg["param_type"] + " f"+str(self.var_function)+"_" + arg["param_name"] + " = uf"+str(
                                        self.var_function)+"_" + arg["param_name"] + ";\n"
                                ],
                            }
                        else:
                            var_curr_gen = {
                                "gen_lines": [
                                    "//GEN_BUILTIN\n",
                                    arg["param_type"].split(
                                        " ")[1] + " uf"+str(self.var_function)+"_" + arg["param_name"] + ";\n",
                                    "memcpy(&u" + arg["param_name"]+", pos, sizeof(" +
                                    arg["param_type"].split(" ")[1] + "));\n",
                                    "pos += sizeof(" +
                                    arg["param_type"].split(" ")[1] + ");\n",
                                    arg["param_type"] + " f"+str(self.var_function)+"_" + arg["param_name"] + " = uf"+str(
                                        self.var_function)+"_" + arg["param_name"] + ";\n"
                                ],
                            }
                            curr_buf_size_arr.append(
                                "sizeof(" + arg["param_type"].split(" ")[1]+")")
                    else:
                        if curr_gen_string == param_id - 1 and curr_gen_string >= 0:
                            var_curr_gen = {
                                "gen_lines": [
                                    "//GEN_SIZE\n",
                                    arg["param_type"].split(" ")[1] + " uf"+str(
                                        self.var_function)+"_" + arg["param_name"] + " = (" + arg["param_type"].split(" ")[1] + ") dyn_size;\n",
                                    arg["param_type"] + " f"+str(self.var_function)+"_" + arg["param_name"] + " = uf"+str(
                                        self.var_function)+"_" + arg["param_name"] + ";\n"
                                ],
                            }
                        else:
                            var_curr_gen = {
                                "gen_lines": [
                                    "//GEN_BUILTIN var\n",
                                    arg["param_type"].split(
                                        " ")[1] + " uf"+str(self.var_function)+"_" + arg["param_name"] + ";\n",
                                    "memcpy(&u" + arg["param_name"]+", pos, sizeof(" +
                                    arg["param_type"].split(" ")[1] + "));\n",
                                    "pos += sizeof(" +
                                    arg["param_type"].split(" ")[1] + ");\n",
                                    arg["param_type"] + " f"+str(self.var_function)+"_" + arg["param_name"] + " = uf"+str(
                                        self.var_function)+"_" + arg["param_name"] + ";\n"
                                ],
                            }
                            curr_buf_size_arr.append(
                                "sizeof(" + arg["param_type"].split(" ")[1]+")")
                else:
                    if arg["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                        if curr_gen_string >= 0:
                            var_curr_gen = self.__gen_size(
                                arg["param_type"], "f"+str(self.var_function)+"_" + arg["param_name"])
                        else:
                            var_curr_gen = self.__gen_builtin(
                                arg["param_type"], "f"+str(self.var_function)+"_" + arg["param_name"])
                            curr_buf_size_arr.append(
                                "sizeof(" + arg["param_type"]+")")
                    else:
                        if curr_gen_string == param_id - 1 and curr_gen_string >= 0:
                            var_curr_gen = self.__gen_size(
                                arg["param_type"], "f"+str(self.var_function)+"_" + arg["param_name"])
                        else:
                            var_curr_gen = self.__gen_builtin(
                                arg["param_type"], "f"+str(self.var_function)+"_" + arg["param_name"])
                            curr_buf_size_arr.append(
                                "sizeof(" + arg["param_type"]+")")
                curr_gen_func_params += var_curr_gen["gen_lines"]

            if arg["generator_type"] == GEN_STRING:
                if (arg["param_usage"] == "FILE_PATH" or arg["param_usage"] == "FILE_PATH_READ" or arg["param_usage"] == "FILE_PATH_WRITE" or arg["param_usage"] == "FILE_PATH_RW"):
                    var_curr_gen = self.__gen_input_file(
                        "f"+str(self.var_function)+"_" + arg["param_name"])
                    self.var_files += 1
                    curr_dyn_size += 1
                    if not var_curr_gen:
                        return None

                    curr_gen_func_params += var_curr_gen["gen_lines"]

                else:
                    var_curr_gen = self.__gen_string(
                        arg["param_type"],
                        "f"+str(self.var_function)+"_" + arg["param_name"],
                        arg["parent_type"])
                    curr_dyn_size += 1
                    if not var_curr_gen:
                        return None
                    curr_gen_func_params += var_curr_gen["gen_lines"]
                    curr_gen_free += var_curr_gen["gen_free"]
                    curr_gen_string = param_id
            param_id += 1

        function_call = "//GEN_VAR_FUNCTION\n    " + func["return_type"] + " " + var_name + \
            " = " + func["name"] + \
            "(" + ",".join(param_list)+");\n"

        # !attempting free on address which was not malloc()-ed
        #
        # if func["return_type_pointer"]:
        #     if func["return_type"].split(" ")[0] != "const" and not parent_func["return_type_pointer"]:
        #         curr_gen_free += ["if(" + var_name+ ") free("+var_name+");\n"]

        curr_gen_func_params.append(function_call)
        return {
            "gen_lines": curr_gen_func_params,
            "gen_free": curr_gen_free,
            "dyn_size": curr_dyn_size,
            "buf_size_arr": curr_buf_size_arr,
        }

    def __wrapper_file(self, func):
        self.target_extension = func["location"].split(":")[-2].split(".")[-1]
        file_index = 1
        qname = func["qname"]
        if len(func["qname"]) > 250:
            return None
        dir_name = qname + str(file_index)

        if not (self.tmp_output_path / qname).exists():
            (self.tmp_output_path / qname
             ).mkdir(parents=True, exist_ok=True)

        # Each variant of fuzz-driver will be save in separated directory
        # inside the directory of function

        while (self.tmp_output_path / qname / dir_name).exists():
            file_index += 1
            dir_name = qname + str(file_index)
            if file_index > 1000:
                break
                
        if file_index > 1000:
            return None
        (self.tmp_output_path / qname /
         dir_name).mkdir(parents=True, exist_ok=True)

        file_name = qname + \
            str(file_index) + "." + self.target_extension

        full_path = (self.tmp_output_path /
                     qname / dir_name / file_name).as_posix()
        f = open(full_path, 'w')
        if f.closed:
            return None
        return f

    def __wrapper_anonymous_file(self, func):
        self.target_extension = func["location"].split(":")[-2].split(".")[-1]
        file_index = 1
        anonymous_path = self.tmp_output_path / "anonymous"
        if not (anonymous_path).exists():
            (anonymous_path).mkdir(parents=True, exist_ok=True)
        name = func["name"]
        if len(func["name"]) > 250:
            return None
        dir_name = name + str(file_index)

        if not (anonymous_path / name).exists():
            (anonymous_path / name
             ).mkdir(parents=True, exist_ok=True)

        # Each variant of fuzz-driver will be save in separated directory
        # inside the directory of function

        while (anonymous_path / name / dir_name).exists():
            file_index += 1
            dir_name = name + str(file_index)
            if file_index > 1000:
                return None

        (anonymous_path / name /
         dir_name).mkdir(parents=True, exist_ok=True)

        file_name = name + \
            str(file_index) + "." + self.target_extension

        full_path = (anonymous_path /
                     name / dir_name / file_name).as_posix()
        f = open(full_path, 'w')
        if f.closed:
            return None
        return f

    def __gen_target_function(self, func, param_id) -> bool:
        malloc_free = [
            "unsigned char *",
            "char *",
        ]

        if param_id == len(func['params']):
            # print("To the end of params!!!! ", param_id)
            if not self.gen_this_function:
                return False
            # If there is no buffer - return!
            if not self.buf_size_arr:
                # print("buf_size failed!!!")
                return False
            # generate file name
            f = self.__wrapper_file(func)
            # print("file ok failed!!!")
            if not f:
                self.gen_this_function = False
                return False
            for line in self.__gen_header(func["location"].split(':')[0]):
                f.write(line)
            f.write('\n')
            compiler_info = self.__get_compile_command(
                func["location"].split(':')[0])
            # print("here1!!!")
            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    f.write(LIBFUZZER_PREFIX_C)
                else:
                    f.write(LIBFUZZER_PREFIX_CXX)
            else:
                f.write(AFLPLUSPLUS_PREFIX)
            if self.dyn_size > 0:
                f.write("    if (Fuzz_Size < " + str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write(") return 0;\n")
                f.write(
                    "    size_t dyn_size = (int) ((Fuzz_Size - (" +
                    str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write("))/" + str(self.dyn_size) + ");\n")
            else:
                if len(self.buf_size_arr) > 0:
                    f.write("    if (Fuzz_Size < ")
                    f.write("+".join(self.buf_size_arr))
                    f.write(") return 0;\n")
            # print("here!!!")
            f.write("    uint8_t * pos = Fuzz_Data;\n")
            for line in self.gen_func_params:
                f.write("    " + line)

            f.write("    //FUNCTION_CALL\n")
            if func["return_type"] in malloc_free:
                f.write("    " + func["return_type"] +
                        " futag_target = " + func["qname"] + "(")
            else:
                f.write("    " + func["qname"] + "(")

            param_list = []
            for arg in func["params"]:
                param_list.append(arg["param_name"] + " ")
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
        # print(" -- info: ", func["name"], ", id:", param_id, ", generator_type: ",curr_param["generator_type"])
        if curr_param["generator_type"] == GEN_BUILTIN:
            if curr_param["param_type"].split(" ")[0] in ["volatile", "const"]:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
            else:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]

            param_id += 1
            self.__gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_STRING:
            if (curr_param["param_usage"] == "FILE_PATH" or curr_param["param_usage"] == "FILE_PATH_READ" or curr_param["param_usage"] == "FILE_PATH_WRITE" or curr_param["param_usage"] == "FILE_PATH_RW" or curr_param["param_name"] == "filename"):
                curr_gen = self.__gen_input_file(curr_param["param_name"])
                self.var_files += 1
                self.dyn_size += 1
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
            else:
                curr_gen = self.__gen_string(
                    curr_param["param_type"],
                    curr_param["param_name"],
                    curr_param["parent_type"])
                self.dyn_size += 1
                if (len(curr_param["parent_type"]) > 0):
                    self.buf_size_arr.append("sizeof(char)")
                else:
                    self.buf_size_arr.append("sizeof(char)")
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
                self.curr_gen_string = param_id

            param_id += 1
            self.__gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_ENUM:  # GEN_ENUM
            found = False
            for enum in self.target_library["enums"]:
                if len(curr_param["param_type"].split(" ")) > 2 and enum["qname"] == curr_param["param_type"].split(" ")[1]:
                    found = True
                    compiler_info = self.__get_compile_command(
                        func["location"].split(':')[0])
                    curr_gen = self.__gen_enum(
                        enum, curr_param["param_name"], compiler_info)
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.buf_size_arr.append("sizeof(unsigned int)")
            if not found:
                self.gen_this_function = False

            param_id += 1
            self.__gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_ARRAY:  # GEN_ARRAY
            self.gen_this_function = False
            curr_gen = self.__gen_array(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_VOID:
            self.gen_this_function = False
            curr_gen = self.__gen_void(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_QUALIFIER:
            curr_gen = self.__gen_qualifier(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"],
                curr_param["parent_gen"],
                param_id
            )
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            if curr_gen["buf_size"]:
                self.buf_size_arr.append(curr_gen["buf_size"])

            param_id += 1
            self.__gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_POINTER:
            curr_gen = self.__gen_pointer(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_STRUCT:
            curr_gen = self.__gen_struct(
                curr_param["param_name"], curr_param["param_type"])
            if not curr_gen:
                self.gen_this_function = False
                return

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_INCOMPLETE:
            # iterate all possible variants for generating
            old_func_params = copy.copy(self.gen_func_params)
            old_gen_free = copy.copy(self.gen_free)
            old_dyn_size = copy.copy(self.dyn_size)
            old_buf_size_arr = copy.copy(self.buf_size_arr)
            old_var_function = copy.copy(self.var_function)
            curr_gen = False
            # print("Search for: ", func["name"], ", ", curr_param["param_name"], " ", curr_param["param_type"])
            found = False
            for f_iter in self.simple_functions:
                # print("Processing: ", f["name"])
                if f_iter["return_type"] == curr_param["param_type"] and f_iter["name"] != func["name"]:
                    found = True
                    # check for function call with simple data type!!!
                    check_params = True
                    for arg in f_iter["params"]:
                        if arg["generator_type"] not in [GEN_BUILTIN, GEN_STRING]:
                            check_params = False
                            break
                    if not check_params:
                        continue
                    curr_gen = self.__gen_var_function(func, f_iter, curr_param["param_name"])
                    self.var_function += 1
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.gen_free += curr_gen["gen_free"]
                    self.dyn_size += curr_gen["dyn_size"]
                    self.buf_size_arr += curr_gen["buf_size_arr"]
                    # print("param id old: ", param_id)
                    param_id += 1
                    # print("param id new: ", param_id)
                    self.__gen_target_function(func, param_id)
                    param_id -= 1
                    # print("param id old2: ", param_id)
                    self.var_function = copy.copy(old_var_function)
                    self.gen_func_params = copy.copy(old_func_params)
                    self.gen_free = copy.copy(old_gen_free)
                    self.dyn_size = copy.copy(old_dyn_size)
                    self.buf_size_arr = copy.copy(old_buf_size_arr)

            # curr_gen = self.gen_incomplete(curr_param["param_name"])
            if not curr_gen or not found:
                self.gen_this_function = False
            # else:
            #     print("gen_var_function ok")

        if curr_param["generator_type"] == GEN_FUNCTION:
            self.gen_this_function = False
            # return null pointer to function?
            curr_gen = self.gen_function(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_UNKNOWN:  # GEN_UNKNOWN
            self.gen_this_function = False
            return None

    def __gen_class_constructor(self, func, param_id) -> bool:
        malloc_free = [
            "unsigned char *",
            "char *",
        ]

        if param_id == len(func['params']):
            if not self.gen_this_function:
                return False
            # If there is no buffer - return!
            if not self.buf_size_arr:
                return False

            # generate file name
            f = self.__wrapper_file(func)
            if not f:
                return False

            for line in self.__gen_header(func["location"].split(':')[0]):
                f.write(line)
            f.write('\n')

            compiler_info = self.__get_compile_command(
                func["location"].split(':')[0])
            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    f.write(LIBFUZZER_PREFIX_C)
                else:
                    f.write(LIBFUZZER_PREFIX_CXX)
            else:
                f.write(AFLPLUSPLUS_PREFIX)
            if self.dyn_size > 0:
                f.write("    if (Fuzz_Size < " + str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write(") return 0;\n")
                f.write(
                    "    size_t dyn_size = (int) ((Fuzz_Size - (" +
                    str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write("))/" + str(self.dyn_size) + ");\n")
            else:
                if len(self.buf_size_arr) > 0:
                    f.write("    if (Fuzz_Size < ")
                    f.write("+".join(self.buf_size_arr))
                    f.write(") return 0;\n")

            f.write("    uint8_t * pos = Fuzz_Data;\n")
            for line in self.gen_func_params:
                f.write("    " + line)

            # Find parent class
            found_parent = None
            for r in self.target_library["records"]:
                if r["hash"] == func["parent_hash"]:
                    found_parent = r
                    break

            if not found_parent:
                self.gen_this_function = False
                return False

            # Find default constructor
            # TODO: add code for other constructors
            f.write("    //declare the RECORD and call constructor\n")
            class_name = found_parent["qname"]
            # print ("Function: ", func["qname"], ", class: ", class_name)
            f.write("    " + class_name + " futag_target" + "(")

            param_list = []
            for arg in func["params"]:
                param_list.append(arg["param_name"] + " ")
            f.write(",".join(param_list))
            f.write(");\n")

            # !attempting free on address which was not malloc()-ed

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
        # print(" -- info: ", func["name"], ", id:", param_id, ", generator_type: ",curr_param["generator_type"])
        if curr_param["generator_type"] == GEN_BUILTIN:
            if curr_param["param_type"].split(" ")[0] in ["volatile", "const"]:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
            else:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]

            param_id += 1
            self.__gen_class_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_STRING:
            if (curr_param["param_usage"] == "FILE_PATH" or curr_param["param_usage"] == "FILE_PATH_READ" or curr_param["param_usage"] == "FILE_PATH_WRITE" or curr_param["param_usage"] == "FILE_PATH_RW" or curr_param["param_name"] == "filename"):
                curr_gen = self.__gen_input_file(curr_param["param_name"])
                self.var_files += 1
                self.dyn_size += 1
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
            else:
                curr_gen = self.__gen_string(
                    curr_param["param_type"],
                    curr_param["param_name"],
                    curr_param["parent_type"])
                self.dyn_size += 1
                if (len(curr_param["parent_type"]) > 0):
                    self.buf_size_arr.append("sizeof(char)")
                else:
                    self.buf_size_arr.append("sizeof(char)")
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
                self.curr_gen_string = param_id

            param_id += 1
            self.__gen_class_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_ENUM:  # GEN_ENUM
            found = False
            for enum in self.target_library["enums"]:
                if enum["name"] == curr_param["param_type"].split(" ")[1]:
                    found = True
                    compiler_info = self.__get_compile_command(
                        func["location"].split(':')[0])
                    curr_gen = self.__gen_enum(
                        enum, curr_param["param_name"], compiler_info)
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.buf_size_arr.append("sizeof(unsigned int)")
            if not found:
                self.gen_this_function = False

            param_id += 1
            self.__gen_class_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_ARRAY:  # GEN_ARRAY
            self.gen_this_function = False
            curr_gen = self.__gen_array(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_VOID:
            self.gen_this_function = False
            curr_gen = self.__gen_void(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_QUALIFIER:
            curr_gen = self.__gen_qualifier(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"],
                curr_param["parent_gen"],
                param_id
            )
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            if curr_gen["buf_size"]:
                self.buf_size_arr.append(curr_gen["buf_size"])

            param_id += 1
            self.__gen_class_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_POINTER:
            curr_gen = self.__gen_pointer(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_STRUCT:
            curr_gen = self.__gen_struct(
                curr_param["param_name"], curr_param["param_type"])
            if not curr_gen:
                self.gen_this_function = False
                return

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_INCOMPLETE:
            # iterate all possible variants for generating
            old_func_params = copy.copy(self.gen_func_params)
            old_gen_free = copy.copy(self.gen_free)
            old_dyn_size = copy.copy(self.dyn_size)
            old_buf_size_arr = copy.copy(self.buf_size_arr)
            old_var_function = copy.copy(self.var_function)
            curr_gen = False
            # print(curr_param["param_type"])
            for f in self.simple_functions:
                if f["return_type"] == curr_param["param_type"] and f["name"] != func["name"]:
                    # check for function call with simple data type!!!
                    check_params = True
                    for arg in f["params"]:
                        if arg["generator_type"] not in [GEN_BUILTIN, GEN_STRING]:
                            check_params = False
                            break
                    if not check_params:
                        continue

                    curr_gen = self.__gen_var_function(func,
                                                     f, curr_param["param_name"])
                    self.var_function += 1
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.gen_free += curr_gen["gen_free"]
                    self.dyn_size += curr_gen["dyn_size"]
                    self.buf_size_arr += curr_gen["buf_size_arr"]
                    param_id += 1
                    self.__gen_class_constructor(func, param_id)

                    param_id -= 1

                    self.gen_func_params = copy.copy(old_func_params)
                    self.gen_free = copy.copy(old_gen_free)
                    self.dyn_size = copy.copy(old_dyn_size)
                    self.buf_size_arr = copy.copy(old_buf_size_arr)
                    self.var_function = copy.copy(old_var_function)

            # curr_gen = self.gen_incomplete(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

        if curr_param["generator_type"] == GEN_FUNCTION:
            self.gen_this_function = False
            # return null pointer to function?
            curr_gen = self.gen_function(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_UNKNOWN:  # GEN_UNKNOWN
            self.gen_this_function = False
            return None

    def __gen_anonymous_constructor(self, func, param_id) -> bool:
        malloc_free = [
            "unsigned char *",
            "char *",
        ]

        if param_id == len(func['params']):
            if not self.gen_this_function:
                return False
            # If there is no buffer - return!
            if not self.buf_size_arr:
                return False

            f = self.__wrapper_anonymous_file(func)
            if not f:
                return False

            for line in self.__gen_header(func["location"].split(':')[0]):
                f.write(line)
            f.write('\n')
            # generate file name
            f = self.__wrapper_file(func)
            if not f:
                return False

            for line in self.__gen_header(func["location"].split(':')[0]):
                f.write(line)
            f.write('\n')
            compiler_info = self.__get_compile_command(
                func["location"].split(':')[0])
            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    f.write(LIBFUZZER_PREFIX_C)
                else:
                    f.write(LIBFUZZER_PREFIX_CXX)
            else:
                f.write(AFLPLUSPLUS_PREFIX)
            if self.dyn_size > 0:
                f.write("    if (Fuzz_Size < " + str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write(") return 0;\n")
                f.write(
                    "    size_t dyn_size = (int) ((Fuzz_Size - (" +
                    str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write("))/" + str(self.dyn_size) + ");\n")
            else:
                if len(self.buf_size_arr) > 0:
                    f.write("    if (Fuzz_Size < ")
                    f.write("+".join(self.buf_size_arr))
                    f.write(") return 0;\n")

            f.write("    uint8_t * pos = Fuzz_Data;\n")
            for line in self.gen_func_params:
                f.write("    " + line)

            # Find parent class
            found_parent = None
            for r in self.target_library["records"]:
                if r["hash"] == func["parent_hash"]:
                    found_parent = r
                    break

            if not found_parent:
                self.gen_this_function = False
                return False

            # Find default constructor
            # TODO: add code for other constructors
            f.write("    //declare the anonymous RECORD and call constructor\n")
            class_name = found_parent["name"]
            # print ("Function: ", func["name"], ", class: ", class_name)
            f.write("    " + class_name + " futag_target" + "(")

            param_list = []
            for arg in func["params"]:
                param_list.append(arg["param_name"] + " ")
            f.write(",".join(param_list))
            f.write(");\n")

            # !attempting free on address which was not malloc()-ed

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
        # print(" -- info: ", func["name"], ", id:", param_id, ", generator_type: ",curr_param["generator_type"])
        if curr_param["generator_type"] == GEN_BUILTIN:
            if curr_param["param_type"].split(" ")[0] in ["volatile", "const"]:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
            else:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]

            param_id += 1
            self.__gen_anonymous_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_STRING:
            if (curr_param["param_usage"] == "FILE_PATH" or curr_param["param_usage"] == "FILE_PATH_READ" or curr_param["param_usage"] == "FILE_PATH_WRITE" or curr_param["param_usage"] == "FILE_PATH_RW" or curr_param["param_name"] == "filename"):
                curr_gen = self.__gen_input_file(curr_param["param_name"])
                self.var_files += 1
                self.dyn_size += 1
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
            else:
                curr_gen = self.__gen_string(
                    curr_param["param_type"].split("::")[-1],
                    curr_param["param_name"],
                    curr_param["parent_type"])
                self.dyn_size += 1
                self.buf_size_arr.append("sizeof(char)")
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
                self.curr_gen_string = param_id

            param_id += 1
            self.__gen_anonymous_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_ENUM:  # GEN_ENUM
            found = False
            for enum in self.target_library["enums"]:
                if enum["name"] == curr_param["param_type"].split(" ")[1].split("::")[-1]:
                    found = True
                    compiler_info = self.__get_compile_command(
                        func["location"].split(':')[0])
                    curr_gen = self.__gen_anonymous_enum(
                        enum, curr_param["param_name"], compiler_info)
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.buf_size_arr.append("sizeof(unsigned int)")
            if not found:
                self.gen_this_function = False

            param_id += 1
            self.__gen_anonymous_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_ARRAY:  # GEN_ARRAY
            self.gen_this_function = False
            curr_gen = self.__gen_array(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_VOID:
            self.gen_this_function = False
            curr_gen = self.__gen_void(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_QUALIFIER:
            curr_gen = self.__gen_qualifier(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"],
                curr_param["parent_gen"],
                param_id
            )
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            if curr_gen["buf_size"]:
                self.buf_size_arr.append(curr_gen["buf_size"])

            param_id += 1
            self.__gen_anonymous_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_POINTER:
            curr_gen = self.__gen_pointer(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_STRUCT:
            curr_gen = self.__gen_struct(
                curr_param["param_name"], curr_param["param_type"])
            if not curr_gen:
                self.gen_this_function = False
                return

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_INCOMPLETE:
            # iterate all possible variants for generating
            old_func_params = copy.copy(self.gen_func_params)
            old_gen_free = copy.copy(self.gen_free)
            old_dyn_size = copy.copy(self.dyn_size)
            old_buf_size_arr = copy.copy(self.buf_size_arr)
            old_var_function = copy.copy(self.var_function)
            curr_gen = False
            # print(curr_param["param_type"])
            for f in self.simple_functions:
                if f["return_type"] == curr_param["param_type"] and f["name"] != func["name"]:
                    # check for function call with simple data type!!!
                    check_params = True
                    for arg in f["params"]:
                        if arg["generator_type"] not in [GEN_BUILTIN, GEN_STRING]:
                            check_params = False
                            break
                    if not check_params:
                        continue

                    curr_gen = self.__gen_var_function(func,
                                                     f, curr_param["param_name"])
                    self.var_function += 1
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.gen_free += curr_gen["gen_free"]
                    self.dyn_size += curr_gen["dyn_size"]
                    self.buf_size_arr += curr_gen["buf_size_arr"]
                    param_id += 1
                    self.__gen_anonymous_constructor(func, param_id)

                    param_id -= 1

                    self.gen_func_params = copy.copy(old_func_params)
                    self.gen_free = copy.copy(old_gen_free)
                    self.dyn_size = copy.copy(old_dyn_size)
                    self.buf_size_arr = copy.copy(old_buf_size_arr)
                    self.var_function = copy.copy(old_var_function)

            # curr_gen = self.gen_incomplete(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

        if curr_param["generator_type"] == GEN_FUNCTION:
            self.gen_this_function = False
            # return null pointer to function?
            curr_gen = self.gen_function(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_constructor(func, param_id)

        if curr_param["generator_type"] == GEN_UNKNOWN:  # GEN_UNKNOWN
            self.gen_this_function = False
            return None

    def __gen_class_method(self, func, param_id) -> bool:
        malloc_free = [
            "unsigned char *",
            "char *",
        ]
        # print("param_id: ", param_id)
        # print(func["params"][param_id])
        if param_id == len(func['params']):

            if not self.gen_this_function:
                return False
            # If there is no buffer - return!
            if not self.buf_size_arr:
                return False

            # generate file name
            f = self.__wrapper_file(func)
            if not f:
                return False

            for line in self.__gen_header(func["location"].split(':')[0]):
                f.write(line)
            f.write('\n')
            compiler_info = self.__get_compile_command(
                func["location"].split(':')[0])
            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    f.write(LIBFUZZER_PREFIX_C)
                else:
                    f.write(LIBFUZZER_PREFIX_CXX)
            else:
                f.write(AFLPLUSPLUS_PREFIX)

            if self.dyn_size > 0:
                f.write("    if (Fuzz_Size < " + str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write(") return 0;\n")
                f.write(
                    "    size_t dyn_size = (int) ((Fuzz_Size - (" +
                    str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write("))/" + str(self.dyn_size) + ");\n")
            else:
                if len(self.buf_size_arr) > 0:
                    f.write("    if (Fuzz_Size < ")
                    f.write("+".join(self.buf_size_arr))
                    f.write(") return 0;\n")

            f.write("    uint8_t * pos = Fuzz_Data;\n")
            for line in self.gen_func_params:
                f.write("    " + line)

            # Find parent class
            found_parent = None
            for r in self.target_library["records"]:
                if r["hash"] == func["parent_hash"]:
                    found_parent = r
                    break

            if not found_parent:
                self.gen_this_function = False
                return False

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
            f.write("    //declare the RECORD\n")
            class_name = found_parent["qname"]
            # print ("Function: ", func["qname"], ", class: ", class_name)
            # declare the RECORD
            f.write("    " + class_name + " futag_target;")
            # call the method
            f.write("    //METHOD CALL\n")
            f.write("    futag_target." + func["name"]+"(")

            param_list = []
            for arg in func["params"]:
                param_list.append(arg["param_name"] + " ")
            f.write(",".join(param_list))
            f.write(");\n")
            # !attempting free on address which was not malloc()-ed
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
        # print(" -- info: ", func["name"], ", id:", param_id, ", generator_type: ",curr_param["generator_type"])
        if curr_param["generator_type"] == GEN_BUILTIN:
            if curr_param["param_type"].split(" ")[0] in ["volatile", "const"]:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
            else:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]

            param_id += 1
            self.__gen_class_method(func, param_id)

        if curr_param["generator_type"] == GEN_STRING:
            if (curr_param["param_usage"] == "FILE_PATH" or curr_param["param_usage"] == "FILE_PATH_READ" or curr_param["param_usage"] == "FILE_PATH_WRITE" or curr_param["param_usage"] == "FILE_PATH_RW" or curr_param["param_name"] == "filename"):
                curr_gen = self.__gen_input_file(curr_param["param_name"])
                self.var_files += 1
                self.dyn_size += 1
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
            else:
                curr_gen = self.__gen_string(
                    curr_param["param_type"],
                    curr_param["param_name"],
                    curr_param["parent_type"])
                self.dyn_size += 1
                if (len(curr_param["parent_type"]) > 0):
                    self.buf_size_arr.append("sizeof(char)")
                else:
                    self.buf_size_arr.append("sizeof(char)")
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
                self.curr_gen_string = param_id

            param_id += 1
            self.__gen_class_method(func, param_id)

        if curr_param["generator_type"] == GEN_ENUM:  # GEN_ENUM
            found = False
            for enum in self.target_library["enums"]:
                if enum["qname"] == curr_param["param_type"].split(" ")[1]:
                    found = True
                    compiler_info = self.__get_compile_command(
                        func["location"].split(':')[0])
                    curr_gen = self.__gen_enum(
                        enum, curr_param["param_name"], compiler_info)
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.buf_size_arr.append("sizeof(unsigned int)")
            if not found:
                self.gen_this_function = False

            param_id += 1
            self.__gen_class_method(func, param_id)

        if curr_param["generator_type"] == GEN_ARRAY:  # GEN_ARRAY
            self.gen_this_function = False
            curr_gen = self.__gen_array(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_method(func, param_id)

        if curr_param["generator_type"] == GEN_VOID:
            self.gen_this_function = False
            curr_gen = self.__gen_void(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_method(func, param_id)

        if curr_param["generator_type"] == GEN_QUALIFIER:
            curr_gen = self.__gen_qualifier(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"],
                curr_param["parent_gen"],
                param_id
            )
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            if curr_gen["buf_size"]:
                self.buf_size_arr.append(curr_gen["buf_size"])

            param_id += 1
            self.__gen_class_method(func, param_id)

        if curr_param["generator_type"] == GEN_POINTER:
            curr_gen = self.__gen_pointer(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_method(func, param_id)

        if curr_param["generator_type"] == GEN_STRUCT:
            curr_gen = self.__gen_struct(
                curr_param["param_name"], curr_param["param_type"])
            if not curr_gen:
                self.gen_this_function = False
                return

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_method(func, param_id)

        if curr_param["generator_type"] == GEN_INCOMPLETE:
            # iterate all possible variants for generating
            old_func_params = copy.copy(self.gen_func_params)
            old_gen_free = copy.copy(self.gen_free)
            old_dyn_size = copy.copy(self.dyn_size)
            old_buf_size_arr = copy.copy(self.buf_size_arr)
            old_var_function = copy.copy(self.var_function)
            curr_gen = False
            # print(curr_param["param_type"])
            for f in self.simple_functions:
                if f["return_type"] == curr_param["param_type"] and f["name"] != func["name"]:
                    # check for function call with simple data type!!!
                    check_params = True
                    for arg in f["params"]:
                        if arg["generator_type"] not in [GEN_BUILTIN, GEN_STRING]:
                            check_params = False
                            break
                    if not check_params:
                        continue

                    curr_gen = self.__gen_var_function(func,
                                                     f, curr_param["param_name"])
                    self.var_function += 1
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.gen_free += curr_gen["gen_free"]
                    self.dyn_size += curr_gen["dyn_size"]
                    self.buf_size_arr += curr_gen["buf_size_arr"]
                    param_id += 1
                    self.__gen_class_method(func, param_id)

                    param_id -= 1

                    self.gen_func_params = copy.copy(old_func_params)
                    self.gen_free = copy.copy(old_gen_free)
                    self.dyn_size = copy.copy(old_dyn_size)
                    self.buf_size_arr = copy.copy(old_buf_size_arr)
                    self.var_function = copy.copy(old_var_function)

            # curr_gen = self.gen_incomplete(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

        if curr_param["generator_type"] == GEN_FUNCTION:
            self.gen_this_function = False
            # return null pointer to function?
            curr_gen = self.gen_function(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_class_method(func, param_id)

        if curr_param["generator_type"] == GEN_UNKNOWN:  # GEN_UNKNOWN
            self.gen_this_function = False
            return None

    def __gen_anonymous_method(self, func, param_id) -> bool:
        malloc_free = [
            "unsigned char *",
            "char *",
        ]
        # print("param_id: ", param_id)
        # print(func["params"][param_id])
        if param_id == len(func['params']):

            if not self.gen_this_function:
                return False
            # If there is no buffer - return!
            if not self.buf_size_arr:
                return False

            # generate file name
            f = self.__wrapper_anonymous_file(func)
            if not f:
                return False

            for line in self.__gen_header(func["location"].split(':')[0]):
                f.write(line)
            f.write('\n')
            compiler_info = self.__get_compile_command(
                func["location"].split(':')[0])
            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    f.write(LIBFUZZER_PREFIX_C)
                else:
                    f.write(LIBFUZZER_PREFIX_CXX)
            else:
                f.write(AFLPLUSPLUS_PREFIX)

            if self.dyn_size > 0:
                f.write("    if (Fuzz_Size < " + str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write(") return 0;\n")
                f.write(
                    "    size_t dyn_size = (int) ((Fuzz_Size - (" +
                    str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write("))/" + str(self.dyn_size) + ");\n")
            else:
                if len(self.buf_size_arr) > 0:
                    f.write("    if (Fuzz_Size < ")
                    f.write("+".join(self.buf_size_arr))
                    f.write(") return 0;\n")

            f.write("    uint8_t * pos = Fuzz_Data;\n")
            for line in self.gen_func_params:
                f.write("    " + line)

            # Find parent class
            found_parent = None
            for r in self.target_library["records"]:
                if r["hash"] == func["parent_hash"]:
                    found_parent = r
                    break

            if not found_parent:
                self.gen_this_function = False
                return False

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
            f.write("    //declare the RECORD\n")
            class_name = found_parent["name"]
            # print ("Function: ", func["name"], ", class: ", class_name)
            # declare the RECORD
            f.write("    " + class_name + " futag_target;")
            # call the method
            f.write("    //METHOD CALL\n")
            f.write("    futag_target." + func["name"]+"(")

            param_list = []
            for arg in func["params"]:
                param_list.append(arg["param_name"] + " ")
            f.write(",".join(param_list))
            f.write(");\n")
            # !attempting free on address which was not malloc()-ed
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
        # print(" -- info: ", func["name"], ", id:", param_id, ", generator_type: ",curr_param["generator_type"])
        if curr_param["generator_type"] == GEN_BUILTIN:
            if curr_param["param_type"].split(" ")[0] in ["volatile", "const"]:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[
                                    1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            "gen_free": []
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(
                                    " ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u" + curr_param["param_name"]+", pos, sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + "));\n",
                                "pos += sizeof(" +
                                curr_param["param_type"].split(" ")[
                                    1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] +
                                " = u" + curr_param["param_name"] + ";\n"
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": []
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1]+")")
            else:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    if self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = self.__gen_size(
                            curr_param["param_type"], curr_param["param_name"])
                    else:
                        curr_gen = self.__gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"]+")")
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]

            param_id += 1
            self.__gen_anonymous_method(func, param_id)

        if curr_param["generator_type"] == GEN_STRING:
            if (curr_param["param_usage"] == "FILE_PATH" or curr_param["param_usage"] == "FILE_PATH_READ" or curr_param["param_usage"] == "FILE_PATH_WRITE" or curr_param["param_usage"] == "FILE_PATH_RW" or curr_param["param_name"] == "filename"):
                curr_gen = self.__gen_input_file(curr_param["param_name"])
                self.var_files += 1
                self.dyn_size += 1
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
            else:
                curr_gen = self.__gen_string(
                    curr_param["param_type"].split("::")[-1],
                    curr_param["param_name"],
                    curr_param["parent_type"])
                self.dyn_size += 1
                if (len(curr_param["parent_type"]) > 0):
                    self.buf_size_arr.append("sizeof(char)")
                else:
                    self.buf_size_arr.append("sizeof(char)")
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
                self.curr_gen_string = param_id

            param_id += 1
            self.__gen_anonymous_method(func, param_id)

        if curr_param["generator_type"] == GEN_ENUM:  # GEN_ENUM
            found = False
            for enum in self.target_library["enums"]:
                if enum["name"] == curr_param["param_type"].split(" ")[1]:
                    found = True
                    compiler_info = self.__get_compile_command(
                        func["location"].split(':')[0])
                    curr_gen = self.__gen_enum(
                        enum, curr_param["param_name"], compiler_info)
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.buf_size_arr.append("sizeof(unsigned int)")
            if not found:
                self.gen_this_function = False

            param_id += 1
            self.__gen_anonymous_method(func, param_id)

        if curr_param["generator_type"] == GEN_ARRAY:  # GEN_ARRAY
            self.gen_this_function = False
            curr_gen = self.__gen_array(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_method(func, param_id)

        if curr_param["generator_type"] == GEN_VOID:
            self.gen_this_function = False
            curr_gen = self.__gen_void(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_method(func, param_id)

        if curr_param["generator_type"] == GEN_QUALIFIER:
            curr_gen = self.__gen_qualifier(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"],
                curr_param["parent_gen"],
                param_id
            )
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            if curr_gen["buf_size"]:
                self.buf_size_arr.append(curr_gen["buf_size"])

            param_id += 1
            self.__gen_anonymous_method(func, param_id)

        if curr_param["generator_type"] == GEN_POINTER:
            curr_gen = self.__gen_pointer(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_method(func, param_id)

        if curr_param["generator_type"] == GEN_STRUCT:
            curr_gen = self.__gen_struct(
                curr_param["param_name"], curr_param["param_type"])
            if not curr_gen:
                self.gen_this_function = False
                return

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_method(func, param_id)

        if curr_param["generator_type"] == GEN_INCOMPLETE:
            # iterate all possible variants for generating
            old_func_params = copy.copy(self.gen_func_params)
            old_gen_free = copy.copy(self.gen_free)
            old_dyn_size = copy.copy(self.dyn_size)
            old_buf_size_arr = copy.copy(self.buf_size_arr)
            old_var_function = copy.copy(self.var_function)
            curr_gen = False
            # print(curr_param["param_type"])
            for f in self.simple_functions:
                if f["return_type"] == curr_param["param_type"] and f["name"] != func["name"]:
                    # check for function call with simple data type!!!
                    check_params = True
                    for arg in f["params"]:
                        if arg["generator_type"] not in [GEN_BUILTIN, GEN_STRING]:
                            check_params = False
                            break
                    if not check_params:
                        continue

                    curr_gen = self.__gen_var_function(func,
                                                     f, curr_param["param_name"])
                    self.var_function += 1
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.gen_free += curr_gen["gen_free"]
                    self.dyn_size += curr_gen["dyn_size"]
                    self.buf_size_arr += curr_gen["buf_size_arr"]
                    param_id += 1
                    self.__gen_anonymous_method(func, param_id)

                    param_id -= 1

                    self.gen_func_params = copy.copy(old_func_params)
                    self.gen_free = copy.copy(old_gen_free)
                    self.dyn_size = copy.copy(old_dyn_size)
                    self.buf_size_arr = copy.copy(old_buf_size_arr)
                    self.var_function = copy.copy(old_var_function)

            # curr_gen = self.gen_incomplete(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

        if curr_param["generator_type"] == GEN_FUNCTION:
            self.gen_this_function = False
            # return null pointer to function?
            curr_gen = self.gen_function(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.__gen_anonymous_method(func, param_id)

        if curr_param["generator_type"] == GEN_UNKNOWN:  # GEN_UNKNOWN
            self.gen_this_function = False
            return None

    def gen_targets(self, anonymous: bool = False):
        """
        Parameters
        ----------
        anonymous: bool
            option for generating fuzz-targets of non-public functions, default to False.
        """
        C_generated_function = []
        C_unknown_function = []
        Cplusplus_usual_class_method = []
        Cplusplus_static_class_method = []
        Cplusplus_anonymous_class_method = []
        for func in self.target_library["functions"]:
            # For C
            if func["access_type"] == AS_NONE and func["fuzz_it"] and func["storage_class"] < 2 and (not "(anonymous namespace)" in func["qname"]) and (func["parent_hash"] == ""):
                print(
                    "-- [Futag] Try to generate fuzz-driver for function: ", func["name"], "...")
                C_generated_function.append(func["name"])
                self.gen_func_params = []
                self.gen_free = []
                self.gen_this_function = True
                self.buf_size_arr = []
                self.dyn_size = 0
                self.curr_gen_string = -1
                result = self.__gen_target_function(func, 0)
                    
            # For C++, Declare object of class and then call the method
            if func["access_type"] == AS_PUBLIC and func["fuzz_it"] and func["func_type"] in [FUNC_CXXMETHOD, FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR, FUNC_GLOBAL, FUNC_STATIC] and (not "::operator" in func["qname"]):
                if (not "(anonymous namespace)" in func["qname"]):
                    Cplusplus_usual_class_method.append(func["qname"])
                    self.gen_func_params = []
                    self.gen_free = []
                    self.gen_this_function = True
                    self.buf_size_arr = []
                    self.dyn_size = 0
                    self.curr_gen_string = -1
                    if func["func_type"] in [FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                        self.__gen_class_constructor(func, 0)
                        if self.gen_this_function:
                            print(
                                "-- [Futag] Fuzz-driver for for constructor: ", func["name"], " generated!")
                    else:
                        self.__gen_class_method(func, 0)
                        if self.gen_this_function:
                            print("-- [Futag] Fuzz-driver for for method: ",
                                  func["name"], " generated!")
                else:
                    Cplusplus_anonymous_class_method.append(func["qname"])
                    if anonymous:
                        self.gen_func_params = []
                        self.gen_free = []
                        self.gen_this_function = True
                        self.buf_size_arr = []
                        self.dyn_size = 0
                        self.curr_gen_string = -1
                        if func["func_type"] in [FUNC_CONSTRUCTOR, FUNC_DEFAULT_CONSTRUCTOR]:
                            self.__gen_anonymous_constructor(func, 0)
                            if self.gen_this_function:
                                print(
                                    "-- [Futag] Fuzz-driver for for constructor: ", func["name"], " generated!")
                        else:
                            self.__gen_anonymous_method(func, 0)
                            if self.gen_this_function:
                                print("-- [Futag] Fuzz-driver for for method: ",
                                    func["name"], " generated!")

            # For C++, Call the static function of class without declaring object
            if func["access_type"] in [AS_NONE, AS_PUBLIC] and func["fuzz_it"] and func["func_type"] in [FUNC_CXXMETHOD, FUNC_GLOBAL, FUNC_STATIC] and func["storage_class"] == SC_STATIC:
                # print("-- [Futag] Try to generate fuzz-driver for static method: ",func["name"], "!")
                if (not "(anonymous namespace)" in func["qname"]) and (not "::operator" in func["qname"]):
                    Cplusplus_static_class_method.append(func["qname"])

            # We dont generate for static function of C
            if func["func_type"] == FUNC_UNKNOW_RECORD and func["storage_class"] == 2:
                C_unknown_function.append(func["qname"])
                continue
        self.result_report = {
            "C_generated_functions": C_generated_function,
            "Cplusplus_static_class_methods": Cplusplus_static_class_method,
            "Cplusplus_usual_class_methods": Cplusplus_usual_class_method,
            "Cplusplus_anonymous_class_methods": Cplusplus_anonymous_class_method,
            "C_unknown_functions": C_unknown_function
        }
        json.dump(self.result_report, open(
            (self.output_path / "result-report.json").as_posix(), "w"))

    def compile_driver_worker(self, bgen_args):
        p = Popen(
            bgen_args["compiler_cmd"],
            stdout=PIPE,
            stderr=PIPE,
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
            print("\n-- [Futag] ERROR on target ", bgen_args["target_name"], ":\n", errors)
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
        target_file.close()
        

    def compile_targets(self, workers: int = 4, keep_failed: bool = False, extra_include: str = "", extra_dynamiclink: str = "", flags: str = FUZZ_COMPILER_FLAGS, coverage: bool=False):
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
                flags = COMPILER_COVERAGE_FLAGS
            else:
                flags = FUZZ_COMPILER_FLAGS

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
            func_file_location = current_func["location"].split(':')[0]
            compiler_info = self.__get_compile_command(func_file_location)
            include_subdir = []
            
            if not os.path.exists(compiler_info["location"]):
                continue
            current_location = os.getcwd()
            os.chdir(compiler_info["location"])
            for iter in compiler_info["command"].split(" "):
                if iter[0:2] == "-I":
                    if pathlib.Path(iter[2:]).exists():
                        include_subdir.append("-I" + pathlib.Path(iter[2:]).absolute().as_posix() + "/")
            os.chdir(current_location)

            if not "-fPIE" in flags:
                compiler_flags_aflplusplus += " -fPIE"
                
            if not "-ferror-limit=1" in flags:
                compiler_flags_libFuzzer += " -ferror-limit=1"
            
            compiler_path = ""
            if self.target_type == LIBFUZZER:
                if compiler_info["compiler"] == "CC":
                    compiler_path = self.futag_llvm_package / "bin/clang"
                else:
                    compiler_path = self.futag_llvm_package / "bin/clang++"
            else:
                compiler_path = self.futag_llvm_package / \
                    "AFLplusplus/usr/local/bin/afl-clang-fast"

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

            # if (self.install_path / "include").exists():
            #     current_include = current_include + [x.parents[0].as_posix() for x in (self.install_path / "include").glob("**/*.h")] + [x.parents[0].as_posix() for x in (self.install_path / "include").glob("**/*.hpp")] 
            
            # current_include = current_include + [(self.build_path).as_posix()]
            # current_include = list(set(current_include))
            
            # for i in resolved_include_paths:
            #     current_include.append("-I" + i.as_posix())
            fuzz_driver_dirs = [x for x in func_dir.iterdir() if x.is_dir()]
            for dir in fuzz_driver_dirs:
                for target_src in [t for t in dir.glob("*"+self.target_extension) if t.is_file()]:
                    target_path = dir.as_posix() + "/" + target_src.stem + ".out"
                    generated_targets += 1
                    if self.target_type == LIBFUZZER:
                        compiler_cmd = [compiler_path.as_posix()] + compiler_flags_libFuzzer.split(" ") + current_include + [extra_include] + [
                            target_src.as_posix()] + ["-o"] + [target_path] + static_lib + [extra_dynamiclink]
                    else:
                        compiler_cmd = [compiler_path.as_posix()] + compiler_flags_aflplusplus.split(" ") + current_include + [extra_include] +[
                            target_src.as_posix()] + ["-o"] + [target_path] + static_lib + [extra_dynamiclink]

                    compile_cmd_list.append({
                        "compiler_cmd" : compiler_cmd,
                        "target_name": target_src.stem,
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
