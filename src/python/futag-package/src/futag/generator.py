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
from futag.sysmsg import *
from futag.preprocessor import *

from subprocess import Popen, PIPE
from multiprocessing import Pool
from typing import List


class Generator:
    """Futag Generator"""

    def __init__(self, futag_llvm_package: str, library_root: str, json_file: str=ANALYSIS_FILE_PATH, output_path = FUZZ_DRIVER_PATH, build_path=BUILD_PATH, install_path=INSTALL_PATH):
        """
        Parameters
        ----------
        json_file: str
            path to the futag-analysis-result.json file
        futag_llvm_package: str
            path to the futag llvm package (with binaries, scripts, etc)
        library_root: str
            path to the library root
        output_path : str
            where to save fuzz-drivers, if this path exists, Futag will delete it and create new one, default "futag-fuzz-drivers"
        build_path: str
            path to the build directory.
        install_path: str
            path to the install directory.
        """

        self.output_path = None  # Path for saving fuzzing drivers
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

        if pathlib.Path(self.futag_llvm_package).exists():
            self.futag_llvm_package = pathlib.Path(self.futag_llvm_package).absolute()
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

            # create directory for function targets if not exists
            if (self.library_root / output_path).exists():
                delete_folder(self.library_root / output_path)
            
            (self.library_root / output_path).mkdir(parents=True, exist_ok=True)
            self.output_path = self.library_root / output_path
        else:
            raise ValueError(INVALID_ANALYSIS_FILE)
        
        if not (self.library_root / build_path).exists():
            raise ValueError(INVALID_BUILPATH)
        self.build_path = self.library_root / build_path

        if not (self.library_root / install_path).exists():
            raise ValueError(INVALID_INSTALLPATH)
        self.install_path = self.library_root / install_path

    def gen_header(self, target_function_fname):
        header = [
            "#include <stdio.h>\n",
            "#include <stddef.h>\n",
            "#include <stdlib.h>\n",
            "#include <string.h>\n",
            "#include <stdint.h>\n"
        ]
        for h in self.target_library['includes'].get(target_function_fname, []):
            header.append(f'#include "{h}"\n')
        return header

    def gen_builtin(self, type_name, var_name):

        return {
            "gen_lines": [
                "//GEN_BUILTIN\n",
                type_name + " " + var_name + ";\n",
                "memcpy(&"+var_name+", pos, sizeof(" + type_name + "));\n",
                "pos += sizeof(" + type_name + ");\n"
            ],
            "gen_free": []
        }
# TODO:!!! qualified type!
        # return {
        #     "gen_lines": [
        #         "//GEN_QUALIFIED\n",
        #         parent_type + " u" + var_name + ";\n",
        #         "memcpy(&u"+var_name+", pos, sizeof(" + parent_type + "));\n",
        #         "pos += sizeof(" + parent_type + ");\n",
        #         type_name + " var_name = u" + var_name + ";\n"
        #     ],
        #     "gen_free": []
        # }

    def gen_size(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_SIZE\n",
                type_name + " " + var_name +
                " = (" + type_name + ") dyn_size;\n",
            ],
            "gen_free": []
        }

    def gen_string(self, type_name, var_name, parent_type):
        if (len(parent_type) > 0):
            return {
                # char  * var_0 = (char  *) malloc(sizeof(char )*(futag_cstr_size + 1));
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
                    "if (dyn_size > 0) {\n",
                    "    free(r" + var_name + ");\n",
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
                "if (dyn_size > 0 ) {\n",
                "    free(" + var_name + ");\n",
                "}\n"
            ]
        }

    def gen_enum(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_ENUM\n"
            ],
            "gen_free": []
        }

    def gen_array(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_ARRAY\n"
            ],
            "gen_free": []
        }

    def gen_void(self, var_name):
        return {
            "gen_lines": [
                "//GEN_VOID\n"
            ],
            "gen_free": []
        }

    def gen_qualifier(self, type_name, var_name, parent_type):
        return {
            "gen_lines": [
                "//GEN_QUALIFIED\n",
                parent_type + " u" + var_name + ";\n",
                "memcpy(&u"+var_name+", pos, sizeof(" + parent_type + "));\n",
                "pos += sizeof(" + parent_type + ");\n",
                type_name + " var_name = u" + var_name + ";\n"
            ],
            "gen_free": []
        }

    def gen_pointer(self, type_name, var_name, parent_type):
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

    def gen_struct(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_STRUCT\n"
            ],
            "gen_free": []
        }

    def gen_input_file(self, var_name):
        cur_gen_free = [ "    " + x  for x in self.gen_free]
        gen_lines = [
            "//GEN_INPUT_FILE\n",
            "const char* " + var_name + " = \"futag_input_file\";\n",
            "FILE *fp = fopen(" + var_name + ",\"w\");\n",
            "if (fp == NULL) {\n",
        ] + cur_gen_free + ["    return 0;\n",
                "}\n",
                "fwrite(pos, 1, dyn_size, fp);\n",
                "fclose(fp);\n",
                "pos += dyn_size;\n"
        ]
        return {
            "gen_lines": gen_lines,
            "gen_free": []
        }

    def check_gen_function(self, function):
        """ Check if we can initialize argument as function call """
        return True

    def gen_var_function(self, parent_func, func, var_name):
        """ Initialize for argument of function call """
        curr_gen_func_params = []
        curr_gen_free = []
        curr_buf_size_arr = []
        curr_dyn_size = 0
        param_list = []
        param_id = 0
        curr_gen_string = -1
        for arg in func["params"]:
            param_list.append("f_" + arg["param_name"])
            if arg["generator_type"] == GEN_BUILTIN:
                if arg["param_type"].split(" ")[0] in ["volatile", "const"]:
                    if arg["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                        var_curr_gen = { 
                            "gen_lines": [
                                "//GEN_SIZE WITH QUALIFIER\n",
                                arg["param_type"].split(" ")[1] + " uf_" + arg["param_name"] + " = (" + arg["param_type"].split(" ")[1] + ") dyn_size;\n",
                                arg["param_type"] + " f_" + arg["param_name"] +" = uf_" +  arg["param_name"] + ";\n"
                            ],
                        }
                    else:
                        if curr_gen_string == param_id - 1 and curr_gen_string >= 0:
                            var_curr_gen = {
                                "gen_lines":[
                                    "//GEN_SIZE\n",
                                    arg["param_type"].split(" ")[1] + " uf_" + arg["param_name"] + " = (" + arg["param_type"].split(" ")[1] + ") dyn_size;\n",
                                    arg["param_type"] + " f_" + arg["param_name"] +" = uf_" +  arg["param_name"] + ";\n"
                                ],
                            }
                        else:
                            # print("GEN_BUILTIN")
                            var_curr_gen = {
                                "gen_lines":[
                                    "//GEN_BUILTIN var\n",
                                    arg["param_type"].split(" ")[1] + " uf_" + arg["param_name"] + ";\n",
                                    "memcpy(&u"+ arg["param_name"]+", pos, sizeof(" + arg["param_type"].split(" ")[1] + "));\n",
                                    "pos += sizeof(" + arg["param_type"].split(" ")[1] + ");\n",
                                    arg["param_type"] + " f_" + arg["param_name"] + " = uf_" +  arg["param_name"] + ";\n"
                                ],
                            }
                            curr_buf_size_arr.append("sizeof(" + arg["param_type"].split(" ")[1]+")")
                else:
                    if arg["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                        # print("GEN_SIZE")
                        var_curr_gen = self.gen_size(
                            arg["param_type"], "f_" + arg["param_name"])
                    else:
                        if curr_gen_string == param_id - 1 and curr_gen_string >= 0:
                            # print("GEN_SIZE")
                            var_curr_gen = self.gen_size(
                            arg["param_type"], "f_" + arg["param_name"])
                        else:
                            # print("GEN_BUILTIN")
                            var_curr_gen = self.gen_builtin(
                                arg["param_type"], "f_" + arg["param_name"])
                            curr_buf_size_arr.append("sizeof(" + arg["param_type"]+")")
                curr_gen_func_params += var_curr_gen["gen_lines"]

            if arg["generator_type"] == GEN_STRING:
                if(arg["param_usage"] == "FILE_PATH" or arg["param_usage"] == "FILE_PATH_READ" or arg["param_usage"] == "FILE_PATH_WRITE" or arg["param_usage"] == "FILE_PATH_RW"):
                    # print("GEN_FILE_PATH")
                    var_curr_gen = self.gen_input_file(
                        "f_" + arg["param_name"])
                    curr_dyn_size += 1
                    if not var_curr_gen:
                        return None

                    curr_gen_func_params += var_curr_gen["gen_lines"]
                    
                else:
                    # print("GEN_STRING")
                    var_curr_gen = self.gen_string(
                        arg["param_type"],
                        "f_" + arg["param_name"],
                        arg["parent_type"])
                    curr_dyn_size += 1
                    if not var_curr_gen:
                        return None
                    curr_gen_func_params += var_curr_gen["gen_lines"]
                    curr_gen_free += var_curr_gen["gen_free"]
                    curr_gen_string = param_id
            param_id += 1
        
        function_call = "//GEN_VAR_FUNCTION\n    " + func["return_type"] + " " + var_name + \
            " = " + func["func_name"] + \
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

    def gen_target_function(self, func, param_id) -> bool:
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
            file_index = 1
            # A short tale how I tried to debug "undefined reference to" for 4
            # hours. If clang sees .cc extension it somehow assumes that it
            # works with c++ (even if we use clang and not clang++) thus
            # when I've tried to link with pure C library I wasn't able to do so.
            # One extra char and whole day worth of debugging.
            # God, I love C!
            
            dir_name = func["func_name"] + str(file_index)
            
            if not (self.output_path / func["func_name"]).exists():
                (self.output_path / func["func_name"]
                 ).mkdir(parents=True, exist_ok=True)

            # Each variant of fuzz-driver will be save in seperated directory 
            # inside the directory of fuction
            
            while (self.output_path / func["func_name"] / dir_name).exists():
                file_index += 1
                dir_name = func["func_name"] + str(file_index)

            (self.output_path / func["func_name"] / dir_name).mkdir(parents=True, exist_ok=True)
            
            file_name = func["func_name"] + str(file_index) + ".c"

            
            full_path = (self.output_path / func["func_name"] / dir_name / file_name).as_posix()
            f = open(full_path, 'w')
            if f.closed:
                return False
            for line in self.gen_header(func["location"].split(':')[0]):
                f.write(line)
            f.write('\n')

            f.write(
                "int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size)\n")
            f.write("{\n")

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

            f.write("    //FUNCTION_CALL\n")
            # generate function call
            # if func["return_type"] != "void":
            #     f.write("    " + func["return_type"] +
            #             " futag_target = " + func["func_name"] + "(")
            # else:
            #     f.write("    futag_target = " + func["func_name"] + "(")
            if func["return_type"] in malloc_free:
                f.write("    " + func["return_type"] +
                        " futag_target = " + func["func_name"] + "(")
            else:
                f.write("    " + func["func_name"] + "(")
            
            param_list = []
            for arg in func["params"]:
                param_list.append(arg["param_name"] + " ")
            f.write(",".join(param_list))
            f.write(");\n")
            
            # !attempting free on address which was not malloc()-ed
            
            if func["return_type"] in malloc_free:
                f.write("    if(futag_target) free(futag_target);\n")

            f.write("    //FREE\n")
            for line in self.gen_free:
                f.write("    " + line)

            f.write("    return 0;\n")
            f.write("}")
            f.close()
            return True

        curr_param = func["params"][param_id]

        if curr_param["generator_type"] == GEN_BUILTIN: 
            if curr_param["param_type"].split(" ")[0] in ["volatile", "const"]:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    curr_gen = { 
                        "gen_lines": [
                            "//GEN_SIZE WITH QUALIFIER\n",
                            curr_param["param_type"].split(" ")[1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                            curr_param["param_type"] + " " + curr_param["param_name"] +" = u" +  curr_param["param_name"] + ";\n"
                        ],
                        "gen_free": []
                    }
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines":[
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[1] + " u" + curr_param["param_name"] + " = (" + curr_param["param_type"].split(" ")[1] + ") dyn_size;\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] + " = u" +  curr_param["param_name"] + ";\n"
                            ],
                            "gen_free":[]
                        }
                    else:
                        # print("GEN_BUILTIN")
                        curr_gen = {
                            "gen_lines":[
                                "//GEN_BUILTIN __\n",
                                curr_param["param_type"].split(" ")[1] + " u" + curr_param["param_name"] + ";\n",
                                "memcpy(&u"+ curr_param["param_name"]+", pos, sizeof(" + curr_param["param_type"].split(" ")[1] + "));\n",
                                "pos += sizeof(" + curr_param["param_type"].split(" ")[1] + ");\n",
                                curr_param["param_type"] + " " + curr_param["param_name"] + " = u" +  curr_param["param_name"] + ";\n"
                            ],
                            "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                        }
                        self.buf_size_arr.append("sizeof(" + curr_param["param_type"].split(" ")[1]+")")
            else:
                if curr_param["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                    # print("GEN_SIZE")
                    curr_gen = self.gen_size(
                        curr_param["param_type"], curr_param["param_name"])
                else:
                    if self.curr_gen_string == param_id - 1 and self.curr_gen_string >= 0:
                        # print("GEN_SIZE")
                        curr_gen = self.gen_size(
                        curr_param["param_type"], curr_param["param_name"])
                    else:
                        # print("GEN_BUILTIN")
                        curr_gen = self.gen_builtin(
                            curr_param["param_type"], curr_param["param_name"])
                        self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_STRING:
            if(curr_param["param_usage"] == "FILE_PATH" or curr_param["param_usage"] == "FILE_PATH_READ" or curr_param["param_usage"] == "FILE_PATH_WRITE" or curr_param["param_usage"] == "FILE_PATH_RW" or curr_param["param_name"] == "filename"):
                # print("GEN_FILE_PATH")
                curr_gen = self.gen_input_file(curr_param["param_name"])
                self.dyn_size += 1
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
            else:
                # print("GEN_STRING")
                curr_gen = self.gen_string(
                    curr_param["param_type"],
                    curr_param["param_name"],
                    curr_param["parent_type"])
                self.dyn_size += 1
                if (len(curr_param["parent_type"]) > 0):
                    self.buf_size_arr.append("sizeof(" + curr_param["parent_type"]+")")
                else:
                    self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
                self.curr_gen_string = param_id

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_ENUM:  # GEN_ENUM
            self.gen_this_function = False
            # print("GEN_ENUM")
            curr_gen = self.gen_enum(
                curr_param["param_type"], curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_ARRAY:  # GEN_ARRAY
            # print("GEN_ARRAY")
            self.gen_this_function = False
            curr_gen = self.gen_array(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_VOID: 
            # print("GEN_VOID")
            self.gen_this_function = False
            curr_gen = self.gen_void(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_QUALIFIER:
            # print("GEN_QUALIFIER")
            curr_gen = self.gen_qualifier(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_POINTER:
            # print("GEN_POINTER")
            curr_gen = self.gen_pointer(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_STRUCT:
            # print("GEN_STRUCT")
            curr_gen = self.gen_struct(curr_param["param_name"], curr_param["param_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_INCOMPLETE:
            # print("GEN_INCOMPLETE")
            # iterate all possible variants for generating
            old_func_params = copy.copy(self.gen_func_params)
            old_gen_free = copy.copy(self.gen_free)
            old_dyn_size = copy.copy(self.dyn_size)
            old_buf_size_arr = copy.copy(self.buf_size_arr)
            curr_gen = False
            for f in self.target_library['functions']:
                if f["return_type"] == curr_param["param_type"] and f["func_name"] != func["func_name"]:
                    # check for function call with simple data type!!!
                    check_params = True
                    for arg in f["params"]:
                        if arg["generator_type"] not in [GEN_BUILTIN, GEN_STRING]:
                            check_params = False
                            break
                    if not check_params:
                        continue

                    curr_gen = self.gen_var_function(func,
                        f, curr_param["param_name"])
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.gen_free += curr_gen["gen_free"]
                    self.dyn_size += curr_gen["dyn_size"]
                    self.buf_size_arr += curr_gen["buf_size_arr"]
                    param_id += 1
                    self.gen_target_function(func, param_id)

                    param_id -= 1

                    self.gen_func_params = copy.copy(old_func_params)
                    self.gen_free = copy.copy(old_gen_free)
                    self.dyn_size = copy.copy(old_dyn_size)
                    self.buf_size_arr = copy.copy(old_buf_size_arr)

            # curr_gen = self.gen_incomplete(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

        if curr_param["generator_type"] == GEN_FUNCTION:
            self.gen_this_function = False
            # print("GEN_FUNCTION")
            # return null pointer to function?
            curr_gen = self.gen_function(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == GEN_UNKNOWN:  # GEN_UNKNOWN
            # print("GEN_UNKNOWN")
            self.gen_this_function = False
            return None

    def gen_targets(self):
        for func in self.target_library["functions"]:
            if(func["fuzz_it"]):
                self.gen_func_params = []
                self.gen_free = []
                self.gen_this_function = True
                self.buf_size_arr = []
                self.dyn_size = 0
                
                self.gen_target_function(func, 0)
                if self.gen_this_function:
                    print("-- [Futag] Fuzz-driver for function: ",func["func_name"], " generated!")

    def compile_driver_worker(self,bgen_args):
        p = Popen(
            bgen_args,
            stdout=PIPE,
            stderr=PIPE,
            universal_newlines=True,
        )
        output, errors = p.communicate()
        if p.returncode:
            print(" ".join(p.args))
            print("\n-- [Futag] ERROR:", errors)
        else:
            print("-- [Futag] Fuzz-driver has been compiled successfully")

    def compile_targets(self, makefile: bool = True, workers: int = 4):
        """
        Parameters
        ----------
        makefile: bool
            option for generating makefile (Makefile.futag)
        workers: int
            number of processes for compiling
        """
        include_subdir: List[pathlib.Path] = [x for x in (self.library_root).iterdir() if x.is_dir()]
        include_subdir = include_subdir + \
            [x for x in (self.build_path).iterdir() if x.is_dir()]
        include_subdir = include_subdir + \
            [x for x in (self.install_path).iterdir() if x.is_dir()]
        if (self.install_path / "include" ).exists():
            include_subdir = include_subdir + \
                [x for x in (self.install_path / "include" ).iterdir() if x.is_dir()]
        generated_functions = [x for x in self.output_path.iterdir() if x.is_dir()]
        generated_targets = 0
        compiler_flags = "-ferror-limit=1 -g -O0 -fsanitize=address,undefined,fuzzer -fprofile-instr-generate -fcoverage-mapping"
        compiler_path = self.futag_llvm_package / "bin/clang"
        compile_cmd_list = []
        static_lib = ["-Wl,--start-group"]
        for target_lib in [u for u in (self.library_root).glob("**/*.a") if u.is_file()]:
            static_lib.append(target_lib.as_posix())
        static_lib.append("-Wl,--end-group")
        for func_dir in generated_functions:
        
            # Extract compiler cwd, to resolve relative includes
            current_func = [f for f in self.target_library['functions'] if f['func_name'] == func_dir.name][0]
            current_func_compilation_opts = current_func['compiler_opts'].split(' ')
            # Extract all include locations from compilation options
            include_paths: List[pathlib.Path] = map(
                pathlib.Path,
                map(
                    current_func_compilation_opts.__getitem__,
                    [i + 1 for i, x in enumerate(current_func_compilation_opts) if x == '-I']
                ))

            resolved_include_paths: List[pathlib.Path] = []
            for include_path in include_paths:
                if include_path.is_absolute():
                    resolved_include_paths.append(include_path)
                else:
                    # Resolve relative include paths (e.g. in this case: -I.. -I.)
                    resolved_include_paths.append(pathlib.Path(include_path).absolute())
            
            current_include = []
            
            for i in include_subdir:
                current_include.append("-I" + i.as_posix())
            for i in resolved_include_paths:
                current_include.append("-I" + i.as_posix())
            fuzz_driver_dirs = [x for x in func_dir.iterdir() if x.is_dir()]
            for dir in fuzz_driver_dirs:
                driver_output = []
                for target_src in [t for t in dir.glob("*.c") if t.is_file()]:
                    generated_targets += 1
                    driver_output.append([current_include, target_src.as_posix(), dir.as_posix() + "/" + target_src.stem + ".out"])
                    compiler_cmd = [compiler_path.as_posix() ] + compiler_flags.split(" ") + current_include + [target_src.as_posix()] + ["-o"] + [dir.as_posix() + "/" + target_src.stem + ".out"] + static_lib
                    target_file = open(target_src.as_posix(), "a")
                    target_file.write("\n//Compile command:")
                    target_file.write("\n/*\n")
                    target_file.write(" ".join(compiler_cmd))
                    target_file.write("\n*/\n")
                    target_file.close()
                    compile_cmd_list.append(compiler_cmd)
        if makefile:
            makefile = open((self.output_path / "Makefile.futag").as_posix(), "w")
            makefile.write("#************************************************\n")
            makefile.write("#*      ______  __  __  ______  ___     ______  *\n")
            makefile.write("#*     / ____/ / / / / /_  __/ /   |   / ____/  *\n")
            makefile.write("#*    / /_    / / / /   / /   / /| |  / / __    *\n")
            makefile.write("#*   / __/   / /_/ /   / /   / ___ | / /_/ /    *\n")
            makefile.write("#*  /_/      \____/   /_/   /_/  |_| \____/     *\n")
            makefile.write("#*                                              *\n")
            makefile.write("#*     Fuzzing target Automated Generator       *\n")
            makefile.write("#*             a tool of ISP RAS                *\n")
            makefile.write("#*                                              *\n")
            makefile.write("#************************************************\n")
            makefile.write("#*This script is used for compiling fuzz drivers*\n")
            makefile.write("#************************************************\n")
            makefile.write("\n")
            makefile.write("COMPILER=" + compiler_path.as_posix() + "\n")
            makefile.write("FLAGS=" + compiler_flags + "\n")
            makefile.write("STATIC_LIBS=" + " ".join(static_lib) + "\n")
            makefile.write("SYS_LIBS=\"\"\n")

            makefile.write("default: \n")
            for d in driver_output:
                makefile.write(
                    "\t"
                    + "${COMPILER} ${FLAGS} "
                    + " ".join(d[0])
                    + d[1]
                    + " -o "
                    + d[2]
                    + " ${STATIC_LIBS} ${SYS_LIBS}\n"
                )
            makefile.write("clean: \n")
            for d in driver_output:
                makefile.write("\trm " + d[1] + "\n")
            makefile.close()
        multi = 1

        with Pool(workers) as p:
            p.map(self.compile_driver_worker, compile_cmd_list)

        # Extract the results of compilation
        compile_targets_list = [x for x in self.output_path.glob("**/*.out") if x.is_file()]
        print(
            "-- [Futag] Result of compiling: "
            + str(len(compile_targets_list))
            + " of "
            + str(generated_targets)
            + " fuzz-driver(s)\n"
        )